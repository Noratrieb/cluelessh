pub struct InteractiveShell {
    line_buf: Vec<u8>,
    out_buf: Vec<u8>,
    should_exit: bool,
}

impl InteractiveShell {
    pub fn new() -> Self {
        let mut this = Self {
            line_buf: Vec::new(),
            out_buf: Vec::new(),
            should_exit: false,
        };
        this.prompt();
        this
    }

    pub fn recv_bytes(&mut self, data: &[u8]) {
        // we're doing a little bit of tty-drivering
        for &byte in data {
            match byte {
                // EOF
                0x04 => {
                    self.should_exit = true;
                    return;
                }
                b'\r' => {
                    let output = if !self.line_buf.is_empty() {
                        super::execute_command(&self.line_buf).stdout
                    } else {
                        Vec::new()
                    };
                    self.line_buf.clear();
                    self.write(b"\r\n");
                    self.write(&output);
                    self.prompt();
                }
                // ESC
                27 => {
                    // We don't handle any of the fancy escape characters, so just drop it to avoid weird behavior.
                }
                // DEL
                127 => {
                    // Backspace, space, backspace.
                    // We literally erase it.
                    if self.line_buf.len() > 0 {
                        self.write(&[8, 32, 8]);
                        self.line_buf.truncate(self.line_buf.len() - 1);
                    }
                }
                _ => {
                    if self.line_buf.len() < 1_000 {
                        self.line_buf.extend_from_slice(&[byte]);
                    }
                    self.write(&[byte]);
                }
            }
        }
    }

    fn prompt(&mut self) {
        self.write(b"# ");
    }

    fn write(&mut self, data: &[u8]) {
        self.out_buf.extend_from_slice(data);
    }

    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

    pub fn bytes_to_write(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out_buf)
    }
}
