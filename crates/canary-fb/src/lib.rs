//! Linux framebuffer (/dev/fb0) emulation.

/// Standard framebuffer dimensions.
pub const FB_WIDTH:  u32 = 1024;
pub const FB_HEIGHT: u32 = 768;
pub const FB_BPP:    u32 = 32;  // bits per pixel (BGRA)
pub const FB_STRIDE: u32 = FB_WIDTH * (FB_BPP / 8);
pub const FB_SIZE:   u32 = FB_STRIDE * FB_HEIGHT;

/// Guest VA where /dev/fb0 is mmap'd by default.
pub const FB_MMAP_ADDR: u64 = 0x5000_0000;

/// ioctl command numbers for /dev/fb0
pub const FBIOGET_VSCREENINFO: u64 = 0x4600;
pub const FBIOPUT_VSCREENINFO: u64 = 0x4601;
pub const FBIOGET_FSCREENINFO: u64 = 0x4602;
pub const FBIOPAN_DISPLAY:     u64 = 0x4606;
pub const FBIO_WAITFORVSYNC:   u64 = 0x40044620;
pub const FBIOGET_CON2FBMAP:   u64 = 0x460f;
pub const FBIOPUT_CON2FBMAP:   u64 = 0x4610;

/// fb_var_screeninfo (Linux kernel struct, 160 bytes).
/// See linux/fb.h
#[repr(C)]
pub struct FbVarScreenInfo {
    pub xres:             u32,
    pub yres:             u32,
    pub xres_virtual:     u32,
    pub yres_virtual:     u32,
    pub xoffset:          u32,
    pub yoffset:          u32,
    pub bits_per_pixel:   u32,
    pub grayscale:        u32,
    pub red_offset:       u32,
    pub red_length:       u32,
    pub red_msb_right:    u32,
    pub green_offset:     u32,
    pub green_length:     u32,
    pub green_msb_right:  u32,
    pub blue_offset:      u32,
    pub blue_length:      u32,
    pub blue_msb_right:   u32,
    pub transp_offset:    u32,
    pub transp_length:    u32,
    pub transp_msb_right: u32,
    pub nonstd:           u32,
    pub activate:         u32,
    pub height:           u32,
    pub width:            u32,
    pub accel_flags:      u32,
    pub pixclock:         u32,
    pub left_margin:      u32,
    pub right_margin:     u32,
    pub upper_margin:     u32,
    pub lower_margin:     u32,
    pub hsync_len:        u32,
    pub vsync_len:        u32,
    pub sync:             u32,
    pub vmode:            u32,
    pub rotate:           u32,
    pub colorspace:       u32,
    pub reserved:         [u32; 4],
}

impl FbVarScreenInfo {
    pub fn default_1024x768_bgra() -> Self {
        FbVarScreenInfo {
            xres: FB_WIDTH, yres: FB_HEIGHT,
            xres_virtual: FB_WIDTH, yres_virtual: FB_HEIGHT,
            xoffset: 0, yoffset: 0,
            bits_per_pixel: FB_BPP,
            grayscale: 0,
            // BGRA layout: Blue=0..8, Green=8..16, Red=16..24, Alpha=24..32
            blue_offset: 0,    blue_length: 8,   blue_msb_right: 0,
            green_offset: 8,   green_length: 8,  green_msb_right: 0,
            red_offset: 16,    red_length: 8,    red_msb_right: 0,
            transp_offset: 24, transp_length: 8, transp_msb_right: 0,
            nonstd: 0, activate: 0,
            height: 0, width: 0, accel_flags: 0,
            pixclock: 39722, left_margin: 48, right_margin: 16,
            upper_margin: 33, lower_margin: 10, hsync_len: 96, vsync_len: 2,
            sync: 0, vmode: 0, rotate: 0, colorspace: 0,
            reserved: [0; 4],
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(160);
        macro_rules! push_u32 {
            ($v:expr) => { bytes.extend_from_slice(&($v).to_le_bytes()); }
        }
        push_u32!(self.xres);          push_u32!(self.yres);
        push_u32!(self.xres_virtual);  push_u32!(self.yres_virtual);
        push_u32!(self.xoffset);       push_u32!(self.yoffset);
        push_u32!(self.bits_per_pixel); push_u32!(self.grayscale);
        push_u32!(self.red_offset);    push_u32!(self.red_length);    push_u32!(self.red_msb_right);
        push_u32!(self.green_offset);  push_u32!(self.green_length);  push_u32!(self.green_msb_right);
        push_u32!(self.blue_offset);   push_u32!(self.blue_length);   push_u32!(self.blue_msb_right);
        push_u32!(self.transp_offset); push_u32!(self.transp_length); push_u32!(self.transp_msb_right);
        push_u32!(self.nonstd);        push_u32!(self.activate);
        push_u32!(self.height);        push_u32!(self.width);         push_u32!(self.accel_flags);
        push_u32!(self.pixclock);      push_u32!(self.left_margin);   push_u32!(self.right_margin);
        push_u32!(self.upper_margin);  push_u32!(self.lower_margin);
        push_u32!(self.hsync_len);     push_u32!(self.vsync_len);
        push_u32!(self.sync);          push_u32!(self.vmode);         push_u32!(self.rotate);
        push_u32!(self.colorspace);
        for r in &self.reserved { push_u32!(r); }
        while bytes.len() < 160 { bytes.push(0); }
        bytes
    }
}

/// fb_fix_screeninfo (Linux kernel struct, 68 bytes).
pub struct FbFixScreenInfo {
    pub id:           [u8; 16],
    pub smem_start:   u64,
    pub smem_len:     u32,
    pub type_:        u32,
    pub type_aux:     u32,
    pub visual:       u32,
    pub xpanstep:     u16,
    pub ypanstep:     u16,
    pub ywrapstep:    u16,
    pub _pad:         u16,
    pub line_length:  u32,
    pub mmio_start:   u64,
    pub mmio_len:     u32,
    pub accel:        u32,
    pub capabilities: u16,
    pub reserved:     [u16; 2],
}

impl FbFixScreenInfo {
    pub fn new(smem_guest_va: u64) -> Self {
        let mut id = [0u8; 16];
        b"Canary FB".iter().enumerate().for_each(|(i, &b)| id[i] = b);
        FbFixScreenInfo {
            id,
            smem_start: smem_guest_va,
            smem_len: FB_SIZE,
            type_: 0,      // FB_TYPE_PACKED_PIXELS
            type_aux: 0,
            visual: 2,     // FB_VISUAL_TRUECOLOR
            xpanstep: 0, ypanstep: 0, ywrapstep: 0, _pad: 0,
            line_length: FB_STRIDE,
            mmio_start: 0, mmio_len: 0, accel: 0, capabilities: 0,
            reserved: [0; 2],
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(68);
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.smem_start.to_le_bytes());
        bytes.extend_from_slice(&self.smem_len.to_le_bytes());
        bytes.extend_from_slice(&self.type_.to_le_bytes());
        bytes.extend_from_slice(&self.type_aux.to_le_bytes());
        bytes.extend_from_slice(&self.visual.to_le_bytes());
        bytes.extend_from_slice(&self.xpanstep.to_le_bytes());
        bytes.extend_from_slice(&self.ypanstep.to_le_bytes());
        bytes.extend_from_slice(&self.ywrapstep.to_le_bytes());
        bytes.extend_from_slice(&self._pad.to_le_bytes());
        bytes.extend_from_slice(&self.line_length.to_le_bytes());
        bytes.extend_from_slice(&self.mmio_start.to_le_bytes());
        bytes.extend_from_slice(&self.mmio_len.to_le_bytes());
        bytes.extend_from_slice(&self.accel.to_le_bytes());
        bytes.extend_from_slice(&self.capabilities.to_le_bytes());
        for r in &self.reserved { bytes.extend_from_slice(&r.to_le_bytes()); }
        while bytes.len() < 68 { bytes.push(0); }
        bytes
    }
}

/// Framebuffer device state.
pub struct Framebuffer {
    /// Guest virtual address where the FB is mmap'd (set when mmap is called).
    pub mmap_addr: Option<u64>,
    pub var_info:  FbVarScreenInfo,
}

impl Framebuffer {
    pub fn new() -> Self {
        Framebuffer {
            mmap_addr: None,
            var_info:  FbVarScreenInfo::default_1024x768_bgra(),
        }
    }

    /// Handle an ioctl on /dev/fb0.
    /// Returns the ioctl result (0 on success, negative errno on failure).
    pub fn ioctl(&mut self, cmd: u64, arg: u64, mem: &mut canary_memory::GuestMemory) -> i64 {
        match cmd {
            FBIOGET_VSCREENINFO => {
                let bytes = self.var_info.as_bytes();
                if mem.write_bytes_at(arg, &bytes).is_err() { return -14; } // EFAULT
                0
            }
            FBIOPUT_VSCREENINFO => {
                // Accept the new var_info as-is (apps may toggle double-buffering etc.).
                0
            }
            FBIOGET_FSCREENINFO => {
                let smem = self.mmap_addr.unwrap_or(FB_MMAP_ADDR);
                let fix = FbFixScreenInfo::new(smem);
                let bytes = fix.as_bytes();
                if mem.write_bytes_at(arg, &bytes).is_err() { return -14; }
                0
            }
            FBIOPAN_DISPLAY   => 0,  // pan = nop
            FBIO_WAITFORVSYNC => 0,  // vsync = instant
            FBIOGET_CON2FBMAP | FBIOPUT_CON2FBMAP => 0,
            _ => -25, // ENOTTY
        }
    }

    /// Read the framebuffer pixel data from guest memory.
    /// Returns a flat BGRA byte slice of width*height*4 bytes, or None if not mapped.
    pub fn read_pixels<'a>(&self, mem: &'a canary_memory::GuestMemory) -> Option<&'a [u8]> {
        let addr = self.mmap_addr?;
        mem.read_bytes(addr, FB_SIZE as usize).ok()
    }
}

impl Default for Framebuffer {
    fn default() -> Self { Self::new() }
}
