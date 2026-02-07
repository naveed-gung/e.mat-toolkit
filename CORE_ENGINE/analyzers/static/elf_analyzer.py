"""
ETHICAL Malware Analysis Toolkit (E.MAT)
ELF (Executable and Linkable Format) File Analyzer

Analyzes Linux ELF files for educational purposes:
- Parse ELF headers and program headers
- List dynamic dependencies
- Extract symbol table
- Analyze sections
"""

import struct
from typing import Dict, List, Optional
from pathlib import Path


class ELFAnalyzer:
    """Analyzes ELF (Linux executable) files"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        
    def analyze(self) -> Dict:
        """
        Perform comprehensive ELF analysis
        
        Returns:
            Dictionary with ELF analysis results
        """
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.dynamic import DynamicSection
            from elftools.elf.sections import SymbolTableSection
            
            with open(self.filepath, 'rb') as f:
                elf = ELFFile(f)
                
                result = {
                    'is_elf': True,
                    'architecture': self._get_architecture(elf),
                    'class': self._get_class(elf),
                    'endianness': self._get_endianness(elf),
                    'type': self._get_type(elf),
                    'entry_point': hex(elf.header['e_entry']),
                    'sections': self._extract_sections(elf),
                    'program_headers': self._extract_program_headers(elf),
                    'dynamic_dependencies': self._extract_dependencies(elf),
                    'symbols': self._extract_symbols(elf),
                    'educational_notes': self._generate_educational_notes(elf)
                }
                
                return result
                
        except ImportError:
            return {
                'is_elf': False,
                'error': 'pyelftools library not installed. Install with: pip install pyelftools'
            }
        except Exception as e:
            return {
                'is_elf': False,
                'error': f'ELF analysis failed: {str(e)}'
            }
    
    def _get_architecture(self, elf) -> str:
        """Determine architecture"""
        machine = elf.header['e_machine']
        architectures = {
            'EM_386': 'x86 (32-bit)',
            'EM_X86_64': 'x86-64 (64-bit)',
            'EM_ARM': 'ARM',
            'EM_AARCH64': 'ARM64',
            'EM_MIPS': 'MIPS',
            'EM_PPC': 'PowerPC',
            'EM_PPC64': 'PowerPC 64-bit',
            'EM_RISCV': 'RISC-V'
        }
        return architectures.get(machine, f'Unknown ({machine})')
    
    def _get_class(self, elf) -> str:
        """Get ELF class (32-bit or 64-bit)"""
        ei_class = elf.header['e_ident']['EI_CLASS']
        return '64-bit' if ei_class == 'ELFCLASS64' else '32-bit'
    
    def _get_endianness(self, elf) -> str:
        """Get endianness"""
        ei_data = elf.header['e_ident']['EI_DATA']
        return 'Little Endian' if ei_data == 'ELFDATA2LSB' else 'Big Endian'
    
    def _get_type(self, elf) -> str:
        """Get ELF type"""
        e_type = elf.header['e_type']
        types = {
            'ET_NONE': 'Unknown',
            'ET_REL': 'Relocatable',
            'ET_EXEC': 'Executable',
            'ET_DYN': 'Shared Object',
            'ET_CORE': 'Core Dump'
        }
        return types.get(e_type, f'Unknown ({e_type})')
    
    def _extract_sections(self, elf) -> List[Dict]:
        """Extract section information"""
        sections = []
        
        for section in elf.iter_sections():
            sections.append({
                'name': section.name,
                'type': section['sh_type'],
                'address': hex(section['sh_addr']),
                'size': section['sh_size'],
                'flags': self._parse_section_flags(section['sh_flags']),
                'educational_note': self._section_educational_note(section.name)
            })
        
        return sections[:20]  # Limit to first 20 sections
    
    def _parse_section_flags(self, flags: int) -> List[str]:
        """Parse section flags"""
        flag_list = []
        if flags & 0x1:
            flag_list.append('WRITE')
        if flags & 0x2:
            flag_list.append('ALLOC')
        if flags & 0x4:
            flag_list.append('EXEC')
        return flag_list
    
    def _section_educational_note(self, name: str) -> str:
        """Provide educational context for sections"""
        notes = {
            '.text': 'Contains executable code',
            '.data': 'Contains initialized data',
            '.bss': 'Contains uninitialized data',
            '.rodata': 'Contains read-only data (constants)',
            '.symtab': 'Contains symbol table',
            '.strtab': 'Contains string table',
            '.dynamic': 'Contains dynamic linking information',
            '.got': 'Global Offset Table for dynamic linking',
            '.plt': 'Procedure Linkage Table for dynamic calls',
            '.init': 'Initialization code',
            '.fini': 'Finalization code'
        }
        return notes.get(name, 'Custom or special-purpose section')
    
    def _extract_program_headers(self, elf) -> List[Dict]:
        """Extract program header information"""
        headers = []
        
        for segment in elf.iter_segments():
            headers.append({
                'type': segment['p_type'],
                'offset': hex(segment['p_offset']),
                'virtual_address': hex(segment['p_vaddr']),
                'physical_address': hex(segment['p_paddr']),
                'file_size': segment['p_filesz'],
                'memory_size': segment['p_memsz'],
                'flags': self._parse_segment_flags(segment['p_flags'])
            })
        
        return headers
    
    def _parse_segment_flags(self, flags: int) -> List[str]:
        """Parse segment flags"""
        flag_list = []
        if flags & 0x1:
            flag_list.append('EXEC')
        if flags & 0x2:
            flag_list.append('WRITE')
        if flags & 0x4:
            flag_list.append('READ')
        return flag_list
    
    def _extract_dependencies(self, elf) -> List[str]:
        """Extract dynamic library dependencies"""
        from elftools.elf.dynamic import DynamicSection
        
        dependencies = []
        
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        dependencies.append(tag.needed)
        
        return dependencies
    
    def _extract_symbols(self, elf) -> Dict:
        """Extract symbol table information"""
        from elftools.elf.sections import SymbolTableSection
        
        symbols = {
            'count': 0,
            'functions': [],
            'objects': [],
            'imported': [],
            'exported': []
        }
        
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    symbols['count'] += 1
                    
                    # Limit to first 30 of each type
                    if symbol['st_info']['type'] == 'STT_FUNC' and len(symbols['functions']) < 30:
                        symbols['functions'].append(symbol.name)
                    elif symbol['st_info']['type'] == 'STT_OBJECT' and len(symbols['objects']) < 30:
                        symbols['objects'].append(symbol.name)
                    
                    # Check if imported or exported
                    if symbol['st_shndx'] == 'SHN_UNDEF' and symbol.name and len(symbols['imported']) < 30:
                        symbols['imported'].append(symbol.name)
                    elif symbol['st_info']['bind'] == 'STB_GLOBAL' and symbol.name and len(symbols['exported']) < 30:
                        symbols['exported'].append(symbol.name)
        
        return symbols
    
    def _generate_educational_notes(self, elf) -> List[str]:
        """Generate educational notes about the ELF file"""
        notes = []
        
        # Architecture note
        arch = self._get_architecture(elf)
        notes.append(f'Architecture: {arch}')
        
        # Type note
        elf_type = self._get_type(elf)
        if elf_type == 'Executable':
            notes.append('Executable file: Can be run directly')
        elif elf_type == 'Shared Object':
            notes.append('Shared library: Used by other programs')
        
        # Dependencies note
        deps = self._extract_dependencies(elf)
        if deps:
            notes.append(f'Depends on {len(deps)} shared libraries')
        
        # Security features
        has_nx = False
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_GNU_STACK':
                flags = segment['p_flags']
                if not (flags & 0x1):  # Not executable
                    has_nx = True
                    notes.append('NX/DEP enabled: Stack is non-executable (security feature)')
                break
        
        return notes


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyzer = ELFAnalyzer(sys.argv[1])
        result = analyzer.analyze()
        
        import json
        print(json.dumps(result, indent=2))
