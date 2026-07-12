use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, Register};

/// addr から始まるバイト列を count 命令分だけ逆アセンブルし、
/// "0x<addr>: <bytes>  <mnemonic>" 形式の文字列にして返す。
pub fn disassemble(bytes: &[u8], addr: u64, count: usize) -> Vec<String> {
    let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut out = Vec::new();
    let mut instr = Instruction::default();
    let mut output = String::new();

    while decoder.can_decode() && out.len() < count {
        decoder.decode_out(&mut instr);
        output.clear();
        formatter.format(&instr, &mut output);

        let start = (instr.ip() - addr) as usize;
        let len = instr.len();
        let raw: Vec<String> = bytes[start..start + len].iter().map(|b| format!("{:02x}", b)).collect();

        out.push(format!("{:#018x}:  {:<24}  {}", instr.ip(), raw.join(" "), output));
    }
    out
}

/// 1命令だけ逆アセンブルして文字列を返す。
pub fn disassemble_one(bytes: &[u8], addr: u64) -> Option<String> {
    disassemble(bytes, addr, 1).into_iter().next()
}

/// DWARF 行情報が無い関数向けのプロローグ検出ヒューリスティック。
/// `endbr64`(任意) → `push rbp` → `mov rbp, rsp` → `sub rsp, imm`(任意) という
/// 典型的なフレームポインタ有りプロローグを検出し、その直後のアドレスを返す。
/// パターンに一致しない場合(フレームポインタ省略ビルド等)は関数先頭のアドレスを
/// そのまま返す。
pub fn skip_prologue_heuristic(bytes: &[u8], addr: u64) -> u64 {
    let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut instr = Instruction::default();

    if !decoder.can_decode() {
        return addr;
    }
    decoder.decode_out(&mut instr);
    if instr.mnemonic() == Mnemonic::Endbr64 {
        if !decoder.can_decode() {
            return addr;
        }
        decoder.decode_out(&mut instr);
    }

    if instr.mnemonic() != Mnemonic::Push || instr.op0_register() != Register::RBP {
        return addr;
    }
    if !decoder.can_decode() {
        return addr;
    }
    decoder.decode_out(&mut instr);
    if instr.mnemonic() != Mnemonic::Mov
        || instr.op0_register() != Register::RBP
        || instr.op1_register() != Register::RSP
    {
        return addr;
    }
    let after_frame_setup = instr.next_ip();

    if decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.mnemonic() == Mnemonic::Sub && instr.op0_register() == Register::RSP {
            return instr.next_ip();
        }
    }
    after_frame_setup
}
