"""
ETHICAL Malware Analysis Toolkit (E.MAT)
PE (Portable Executable) File Analyzer

Analyzes Windows PE files for educational purposes:
- Parse PE headers (DOS, NT, Optional)
- Extract sections (.text, .data, .rdata, etc.)
- List imports and exports with educational risk scoring
- Extract resources
- Detect common packers
- Extract compile timestamp
"""

import struct
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path


class PEAnalyzer:
    """Analyzes PE (Windows executable) files"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = None
        self.pe_offset = None
        
    def analyze(self) -> Dict:
        """
        Perform comprehensive PE analysis
        
        Returns:
            Dictionary with PE analysis results
        """
        try:
            import pefile
            
            pe = pefile.PE(self.filepath)
            
            result = {
                'is_pe': True,
                'architecture': self._get_architecture(pe),
                'subsystem': self._get_subsystem(pe),
                'compile_timestamp': self._get_compile_time(pe),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'sections': self._extract_sections(pe),
                'imports': self._extract_imports(pe),
                'exports': self._extract_exports(pe),
                'resources': self._extract_resources(pe),
                'packer_detection': self._detect_packers(pe),
                'educational_notes': self._generate_educational_notes(pe)
            }
            
            pe.close()
            return result
            
        except ImportError:
            return {
                'is_pe': False,
                'error': 'pefile library not installed. Install with: pip install pefile'
            }
        except Exception as e:
            return {
                'is_pe': False,
                'error': f'PE analysis failed: {str(e)}'
            }
    
    def _get_architecture(self, pe) -> str:
        """Determine architecture (32-bit or 64-bit)"""
        import pefile
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return 'x86 (32-bit)'
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return 'x64 (64-bit)'
        else:
            return f'Unknown (0x{pe.FILE_HEADER.Machine:04x})'
    
    def _get_subsystem(self, pe) -> str:
        """Get subsystem type"""
        subsystems = {
            1: 'Native',
            2: 'Windows GUI',
            3: 'Windows CUI (Console)',
            5: 'OS/2 CUI',
            7: 'POSIX CUI',
            9: 'Windows CE GUI',
            10: 'EFI Application',
            11: 'EFI Boot Service Driver',
            12: 'EFI Runtime Driver',
            13: 'EFI ROM',
            14: 'XBOX',
            16: 'Windows Boot Application'
        }
        subsystem_id = pe.OPTIONAL_HEADER.Subsystem
        return subsystems.get(subsystem_id, f'Unknown ({subsystem_id})')
    
    def _get_compile_time(self, pe) -> str:
        """Extract compile timestamp"""
        timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return f'Invalid timestamp (0x{timestamp:08x})'
    
    def _extract_sections(self, pe) -> List[Dict]:
        """Extract section information"""
        sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sections.append({
                'name': name,
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
                'characteristics': self._parse_section_characteristics(section.Characteristics),
                'educational_note': self._section_educational_note(name, section.get_entropy())
            })
        return sections
    
    def _parse_section_characteristics(self, characteristics: int) -> List[str]:
        """Parse section characteristics flags"""
        flags = []
        if characteristics & 0x20:
            flags.append('CODE')
        if characteristics & 0x40:
            flags.append('INITIALIZED_DATA')
        if characteristics & 0x80:
            flags.append('UNINITIALIZED_DATA')
        if characteristics & 0x20000000:
            flags.append('EXECUTABLE')
        if characteristics & 0x40000000:
            flags.append('READABLE')
        if characteristics & 0x80000000:
            flags.append('WRITABLE')
        return flags
    
    def _section_educational_note(self, name: str, entropy: float) -> str:
        """Provide educational context for sections"""
        notes = {
            '.text': 'Contains executable code',
            '.data': 'Contains initialized data',
            '.rdata': 'Contains read-only data (constants, strings)',
            '.bss': 'Contains uninitialized data',
            '.rsrc': 'Contains resources (icons, strings, etc.)',
            '.reloc': 'Contains relocation information'
        }
        
        note = notes.get(name, 'Custom or unusual section name')
        
        if entropy > 7.0:
            note += ' - HIGH ENTROPY: May be packed or encrypted'
        
        return note
    
    def _extract_imports(self, pe) -> List[Dict]:
        """Extract imported DLLs and functions with risk scoring"""
        imports = []
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            functions = []
            
            for imp in entry.imports[:50]:  # Limit to first 50 functions
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    functions.append({
                        'name': func_name,
                        'risk_level': self._assess_function_risk(func_name),
                        'educational_note': self._function_educational_note(func_name)
                    })
            
            imports.append({
                'dll': dll_name,
                'function_count': len(entry.imports),
                'functions': functions,
                'dll_risk': self._assess_dll_risk(dll_name)
            })
        
        return imports
    
    def _assess_function_risk(self, func_name: str) -> str:
        """Educational risk assessment for API functions"""
        high_risk = ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 
                     'SetWindowsHookEx', 'GetAsyncKeyState', 'RegSetValueEx']
        medium_risk = ['CreateProcess', 'ShellExecute', 'WinExec', 'URLDownloadToFile',
                       'InternetOpen', 'CreateFile', 'WriteFile']
        
        if any(risky in func_name for risky in high_risk):
            return 'HIGH'
        elif any(risky in func_name for risky in medium_risk):
            return 'MEDIUM'
        return 'LOW'
    
    def _function_educational_note(self, func_name: str) -> str:
        """Provide educational context for functions"""
        notes = {
            'CreateRemoteThread': 'Can inject code into other processes',
            'WriteProcessMemory': 'Can modify memory of other processes',
            'VirtualAllocEx': 'Allocates memory in other processes',
            'SetWindowsHookEx': 'Can intercept system events (keylogging)',
            'GetAsyncKeyState': 'Can capture keyboard input',
            'RegSetValueEx': 'Modifies Windows registry',
            'CreateProcess': 'Spawns new processes',
            'InternetOpen': 'Initiates network connections',
            'URLDownloadToFile': 'Downloads files from internet'
        }
        
        for key, note in notes.items():
            if key in func_name:
                return note
        
        return 'Standard Windows API function'
    
    def _assess_dll_risk(self, dll_name: str) -> str:
        """Assess risk level of imported DLL"""
        high_risk_dlls = ['ws2_32.dll', 'wininet.dll', 'urlmon.dll']
        
        if dll_name.lower() in high_risk_dlls:
            return 'MEDIUM (Network-related)'
        return 'LOW'
    
    def _extract_exports(self, pe) -> List[str]:
        """Extract exported functions"""
        exports = []
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports
        
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:50]:  # Limit to first 50
            if exp.name:
                exports.append(exp.name.decode('utf-8', errors='ignore'))
        
        return exports
    
    def _extract_resources(self, pe) -> Dict:
        """Extract resource information"""
        resources = {
            'has_resources': False,
            'types': [],
            'count': 0
        }
        
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resources['has_resources'] = True
            
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name:
                    res_name = str(resource_type.name)
                else:
                    res_name = str(resource_type.struct.Id)
                
                resources['types'].append(res_name)
                resources['count'] += 1
        
        return resources
    
    def _detect_packers(self, pe) -> Dict:
        """Detect common packers/protectors"""
        detection = {
            'likely_packed': False,
            'indicators': [],
            'detected_packers': []
        }
        
        # Check for high entropy in .text section
        for section in pe.sections:
            if b'.text' in section.Name:
                if section.get_entropy() > 7.0:
                    detection['likely_packed'] = True
                    detection['indicators'].append('High entropy in code section')
        
        # Check for common packer section names
        packer_sections = {
            b'UPX0': 'UPX',
            b'UPX1': 'UPX',
            b'.aspack': 'ASPack',
            b'.adata': 'ASPack',
            b'.petite': 'Petite',
            b'.ndata': 'NSPack'
        }
        
        for section in pe.sections:
            for packer_name, packer in packer_sections.items():
                if packer_name in section.Name:
                    detection['detected_packers'].append(packer)
                    detection['likely_packed'] = True
        
        # Check for unusual entry point
        for section in pe.sections:
            if (pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress and
                pe.OPTIONAL_HEADER.AddressOfEntryPoint < section.VirtualAddress + section.Misc_VirtualSize):
                if b'.text' not in section.Name and b'CODE' not in section.Name:
                    detection['indicators'].append(f'Entry point in unusual section: {section.Name.decode("utf-8", errors="ignore")}')
        
        return detection
    
    def _generate_educational_notes(self, pe) -> List[str]:
        """Generate educational notes about the PE file"""
        notes = []
        
        # Architecture note
        if 'x64' in self._get_architecture(pe):
            notes.append('64-bit executable: Can access more memory, common in modern software')
        else:
            notes.append('32-bit executable: Compatible with older systems, still widely used')
        
        # Subsystem note
        subsystem = self._get_subsystem(pe)
        if 'Console' in subsystem:
            notes.append('Console application: Runs in command-line window')
        elif 'GUI' in subsystem:
            notes.append('GUI application: Has graphical user interface')
        
        # Import note
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            notes.append(f'Imports from {dll_count} DLLs: Shows dependencies on system libraries')
        
        return notes


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyzer = PEAnalyzer(sys.argv[1])
        result = analyzer.analyze()
        
        import json
        print(json.dumps(result, indent=2))
