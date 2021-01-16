import os
import sys
import time
import re

#binary_file_arch: distinguish Big-Endian and Little-Endian
#file -b output example: Mach-O 64-bit executable arm64 
#
def binary_file_arch(path):
    binary_file_arch = os.popen('file -b ' + path).read().split(' ')[-1].strip()
    return binary_file_arch

def pointers_from_binary(line, binary_file_arch): 
    print(line)
    lines = line.split("\t")
    if len(lines) == 2:
        line = lines[1].strip().split(' ')
    else:
        line = line[16:].strip().split(' ')
    pointers = set()
    if binary_file_arch == 'x86_64':
        #untreated line example:00000001030cec80 d8 75 15 03 01 00 00 00 68 77 15 03 01 00 00 00 
        pointers.add(''.join(line[4:8][::-1] + line[0:4][::-1]))
        pointers.add(''.join(line[12:16][::-1] + line[8:12][::-1]))
        return pointers
    #arm64 confirmed,armv7 arm7s unconfirmed 
    if binary_file_arch.startswith('arm'):
    #untreated line example:00000001030bcd20 03138580 00000001 03138878 00000001 
        if len(line) >= 2:
            pointers.add(line[1] + line[0])
        if len(line) >= 4:
            pointers.add(line[3] + line[2])
    return pointers

#通过otool -v -s __DATA __objc_classrefs获取到引用类的地址。
def class_ref_pointers(path, binary_file_arch):
    ref_pointers = set()
    lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classrefs %s' % path).readlines() 
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        ref_pointers = ref_pointers.union(pointers)
    return ref_pointers

#通过otool -v -s __DATA __objc_classlist获取所有类的地址。
def class_list_pointers(path, binary_file_arch):
    list_pointers = set()
    #__DATA_CONST __DATA
    command = '/usr/bin/otool -v -s __DATA __objc_classlist %s' % path
    lines = os.popen(command).readlines() 
    if len(lines) < 2:
        command = '/usr/bin/otool -v -s __DATA_CONST __objc_classlist %s' % path
        lines = os.popen(command).readlines() 
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        list_pointers = list_pointers.union(pointers) 
    return list_pointers

#获取未被使用到类
def class_unrefpointers(path, binary_file_arch):
    list_pointers =  class_list_pointers(path, binary_file_arch)
    ref_pointers = class_ref_pointers(path, binary_file_arch)
    unref_pointers = list_pointers - ref_pointers
    return unref_pointers

#通过nm -nm命令可以得到地址和对应的类名字。
def class_symbols(path):
    symbols = {}
    #class symbol format from nm: 0000000103113f68 (__DATA,__objc_data) external _OBJC_CLASS_$_EpisodeStatusDetailItemView  
    re_class_name = re.compile('(\w{16}) .* _OBJC_CLASS_\$_(.+)') 
    lines = os.popen('nm -nm %s' % path).readlines()
    for line in lines:
        result = re_class_name.findall(line) 
        if result:
            (address, symbol) = result[0]
            symbols[address] = symbol 
    return symbols


#在实际分析的过程中发现，如果一个类的子类被实例化，父类未被实例化，此时父类不会出现在__objc_classrefs这个段里， 在未使用的类中需要将这一部分父类过滤出去。使用otool -oV可以获取到类的继承关系。
def filter_super_class(path, unref_symbols):
    re_subclass_name = re.compile("\w{16} 0x\w{9} _OBJC_CLASS_\$_(.+)")
    re_superclass_name = re.compile("\s*superclass 0x\w{9} _OBJC_CLASS_\$_(.+)")
    #subclass example: 0000000102bd8070 0x103113f68 _OBJC_CLASS_$_TTEpisodeStatusDetailItemView #superclass example: superclass 0x10313bb80 _OBJC_CLASS_$_TTBaseControl
    lines = os.popen("/usr/bin/otool -oV %s" % path).readlines()
    subclass_name = ""
    superclass_name = ""
    for line in lines:
        subclass_match_result = re_subclass_name.findall(line) 
        if subclass_match_result:
            subclass_name = subclass_match_result[0] 
            superclass_match_result = re_superclass_name.findall(line) 
        if superclass_match_result:
            superclass_name = superclass_match_result[0]
        if len(subclass_name) > 0 and len(superclass_name) > 0:
            if superclass_name in unref_symbols and subclass_name not in unref_symbols:
                unref_symbols.remove(superclass_name) 
                superclass_name = ""
                subclass_name = ""
    return unref_symbols

def filterSDKClass(unref_pointers, symbols, unref_symbols, reserved_prefix, filter_prefix):
    for unref_pointer in unref_pointers: 
        if unref_pointer in symbols:
            unref_symbol = symbols[unref_pointer]
            if len(reserved_prefix) > 0 and not unref_symbol.startswith(reserved_prefix):
                continue
            if len(filter_prefix) > 0 and unref_symbol.startswith(filter_prefix):
                continue 
            unref_symbols.add(unref_symbol)

def beginParsePath(path):
    symbols = class_symbols(path)
    script_path = sys.path[0].strip()
    f = open(script_path+"/result.txt","w")
    arch = binary_file_arch(path)
    unrefPoint = class_unrefpointers(path,arch)
    #f.write( "unref class number: %d\n" % len(unref_symbles)) 
    for key in unrefPoint:
        if key in symbols.keys():
            f.write("UNUsed Class:")
            f.write(key)
            f.write(":")
            f.write(symbols[key])
            f.write("\n")
        else:
            f.write("UNUsed Class:")
            f.write(key)
            f.write("\n")
    f.write("\n")
    f.close()

if __name__ == "__main__":
    from sys import argv
    if len(argv) == 2:
        print("begin ####\n")
        print(argv[1])
        beginParsePath(argv[1])
        print("end ######\n")