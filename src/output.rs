//! Best-effort decoding of captured subprocess output for display.

use std::borrow::Cow;

/// Keep one fallback encoding for both progress previews and completed output.
pub(crate) struct OutputDecoder {
    #[cfg(windows)]
    code_page: u32,
}

impl Default for OutputDecoder {
    fn default() -> Self {
        Self {
            #[cfg(windows)]
            // SAFETY: GetConsoleOutputCP takes no arguments and accesses no Rust memory.
            code_page: unsafe { windows_sys::Win32::System::Console::GetConsoleOutputCP() },
        }
    }
}

impl OutputDecoder {
    #[cfg(all(windows, test))]
    pub(crate) fn with_code_page(code_page: u32) -> Self {
        Self { code_page }
    }

    pub(crate) fn decode<'a>(&self, bytes: &'a [u8]) -> Cow<'a, str> {
        // Many tools always emit UTF-8, independently of the console settings.
        if let Ok(text) = std::str::from_utf8(bytes) {
            return Cow::Borrowed(text);
        }

        #[cfg(windows)]
        if let Some(text) = self.decode_code_page(bytes) {
            return Cow::Owned(text);
        }

        String::from_utf8_lossy(bytes)
    }

    #[cfg(windows)]
    fn decode_code_page(&self, bytes: &[u8]) -> Option<String> {
        use std::convert::TryFrom;
        use windows_sys::Win32::Globalization::{MultiByteToWideChar, MB_ERR_INVALID_CHARS};

        // GetConsoleOutputCP returns 0 without an attached console. Passing 0
        // to MultiByteToWideChar would instead select the unrelated ANSI page.
        if self.code_page == 0 {
            return None;
        }
        let input_len = i32::try_from(bytes.len()).ok()?;

        // SAFETY: The input pointer covers input_len bytes. A null output with
        // zero capacity queries the required number of UTF-16 code units.
        let required = unsafe {
            MultiByteToWideChar(
                self.code_page,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                input_len,
                std::ptr::null_mut(),
                0,
            )
        };
        if required == 0 {
            return None;
        }

        let mut wide = vec![0u16; required as usize];
        // SAFETY: The input, flags, and numeric code page are unchanged. wide
        // contains required writable u16 elements, not required bytes. Explicit
        // input lengths preserve embedded NULs and never scan beyond the slice.
        let written = unsafe {
            MultiByteToWideChar(
                self.code_page,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                input_len,
                wide.as_mut_ptr(),
                required,
            )
        };
        if written == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&wide[..written as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_is_preserved() {
        let decoder = OutputDecoder::default();
        for text in ["", "diagnostic\r\n", "测试 é 😀\0end"] {
            assert!(matches!(decoder.decode(text.as_bytes()), Cow::Borrowed(s) if s == text));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_output_remains_lossy_utf8() {
        assert_eq!(
            OutputDecoder::default().decode(b"missing-\x82.obj"),
            "missing-�.obj"
        );
    }

    #[cfg(windows)]
    #[test]
    fn utf8_takes_priority_over_the_console_code_page() {
        let decoder = OutputDecoder { code_page: 437 };
        assert_eq!(decoder.decode("missing-é.obj".as_bytes()), "missing-é.obj");
    }

    #[cfg(windows)]
    #[test]
    fn console_code_page_decodes_non_utf8_output() {
        // The same byte has different meanings in the OEM and ANSI code pages.
        assert_eq!(OutputDecoder { code_page: 437 }.decode(b"\x82"), "é");
        assert_eq!(OutputDecoder { code_page: 1252 }.decode(b"\x82"), "‚");
        assert_eq!(
            OutputDecoder { code_page: 936 }.decode(
                b"\xd5\xfd\xd4\xda\xb4\xb4\xbd\xa8\xbf\xe2 missing-\xb2\xe2\xca\xd4.lib \xba\xcd\xb6\xd4\xcf\xf3 missing-\xb2\xe2\xca\xd4.exp\r\n"
            ),
            "正在创建库 missing-测试.lib 和对象 missing-测试.exp\r\n"
        );
    }

    #[cfg(windows)]
    #[test]
    fn conversion_preserves_embedded_nuls_and_surrogate_pairs() {
        assert_eq!(
            OutputDecoder { code_page: 437 }.decode(b"a\0\x82z"),
            "a\0éz"
        );
        assert_eq!(
            OutputDecoder { code_page: 54936 }.decode(b"\x94\x39\xfc\x36"),
            "😀"
        );
    }

    #[cfg(windows)]
    #[test]
    fn unavailable_or_invalid_conversion_falls_back_to_lossy_utf8() {
        for code_page in [0, u32::MAX, 65001, 936, 50220] {
            // 0 means no console, 936 rejects a lone lead byte, and 50220 does
            // not support MB_ERR_INVALID_CHARS. All failures retain the fallback.
            assert_eq!(
                OutputDecoder { code_page }.decode(b"missing-\x81"),
                "missing-�"
            );
        }
    }
}
