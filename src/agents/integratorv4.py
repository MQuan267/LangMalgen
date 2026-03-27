from __future__ import annotations
import os, json, ast, time, re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI, RateLimitError

def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

class UniversalCodeAnalyzer:
    """
    Universal code analyzer - NO hardcoded key names
    Phân tích code để hiểu module đang làm gì
    """
    
    @staticmethod
    def analyze_module(code: str, module_info: Dict) -> Dict[str, Any]:
        """Deep analysis - works for ANY keys"""
        
        analysis = {
            'id': module_info['id'],
            'name': module_info['name'],
            'type': module_info['type'],
            'desc': module_info.get('desc', ''),
            'needs_input': False,
            'input_keys': set(),
            'output_keys': set(),
            'is_independent': False,
            'data_sources': [],
            'operations': [],
            'has_blocking_code': False,
            'blocking_duration': None,
            'issues': []
        }
        
        try:
            tree = ast.parse(code)
        except:
            analysis['issues'].append('parse_failed')
            return analysis
        
        run_func = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'run':
                run_func = node
                break
        
        if not run_func:
            analysis['issues'].append('no_run_function')
            return analysis
        
        source_code = ast.unparse(run_func)
        
        # === DETECT INPUT KEYS (ALL PATTERNS) ===
        for node in ast.walk(run_func):
            # Pattern 1: input_data.get('key')
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == 'input_data' and 
                        node.func.attr == 'get'):
                        if node.args and isinstance(node.args[0], ast.Constant):
                            analysis['input_keys'].add(node.args[0].value)
            
            # Pattern 2: input_data['key']
            elif isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Name) and node.value.id == 'input_data':
                    if isinstance(node.slice, ast.Constant):
                        analysis['input_keys'].add(node.slice.value)
        
        # Check if input_data is used without specific keys
        if 'input_data' in source_code:
            uses = source_code.count('input_data')
            checks = source_code.count('input_data is None') + source_code.count('if not input_data')
            
            if uses > checks + 1:
                analysis['needs_input'] = True
        
        analysis['needs_input'] = analysis['needs_input'] or len(analysis['input_keys']) > 0
        
        # === DETECT INDEPENDENCE (data collection tasks) ===
        real_data_sources = [
            # Keyboard/input capture
            'keyboard.Listener', 'keyboard.on_press', 'pynput',
            # System commands
            'subprocess.run', 'subprocess.Popen', 'subprocess.check_output',
            # System info
            'psutil.process_iter', 'psutil.cpu_', 'psutil.virtual_memory',
            'platform.system', 'platform.uname', 'platform.linux_distribution',
            # File system
            'os.listdir', 'os.walk', 'os.scandir', 'glob.glob',
            # Network
            'socket.socket', 'socket.recv', 'socket.accept',
            # Windows-specific
            'win32api', 'win32con', 'win32gui', 'win32crypt',
            # Screenshots
            'PIL.ImageGrab', 'ImageGrab.grab',
            'ctypes.windll',
            # Browser/credential access
            'sqlite3.connect', 'chrome', 'firefox', 'credentials'
        ]
        
        for source in real_data_sources:
            if source.lower() in source_code.lower():
                analysis['data_sources'].append(source)
        
        # Independent if has data sources AND doesn't require external input
        if analysis['data_sources']:
            optional_input_patterns = [
                'if input_data is None',
                'if not input_data',
                'input_data or {}',
                'input_data = input_data or',
                'input_data if input_data else'
            ]
            
            has_optional_input = any(p in source_code for p in optional_input_patterns)
            
            if not analysis['needs_input'] or has_optional_input:
                analysis['is_independent'] = True
        
        # === DETECT OUTPUT KEYS ===
        for node in ast.walk(run_func):
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Dict):
                    for key, value in zip(node.value.keys, node.value.values):
                        if isinstance(key, ast.Constant) and key.value == 'data':
                            if isinstance(value, ast.Dict):
                                for dk in value.keys:
                                    if isinstance(dk, ast.Constant):
                                        analysis['output_keys'].add(dk.value)
                            elif isinstance(value, ast.Name):
                                var_name = value.id
                                for n in ast.walk(run_func):
                                    if isinstance(n, ast.Assign):
                                        for target in n.targets:
                                            if isinstance(target, ast.Name) and target.id == var_name:
                                                if isinstance(n.value, ast.Dict):
                                                    for vk in n.value.keys:
                                                        if isinstance(vk, ast.Constant):
                                                            analysis['output_keys'].add(vk.value)
        
        # === DETECT OPERATIONS ===
        if 'json.dumps' in source_code or 'json.loads' in source_code:
            analysis['operations'].append('serialize')
        if any(x in source_code for x in ['AES', 'encrypt', 'Cipher', 'Fernet', 'RSA']):
            analysis['operations'].append('encrypt')
        if any(x in source_code for x in ['requests.post', 'requests.get', 'urllib', 'http.client']):
            analysis['operations'].append('http')
        if 'open(' in source_code and ('w' in source_code or 'a' in source_code):
            analysis['operations'].append('file_write')
        if 'subprocess.' in source_code:
            analysis['operations'].append('subprocess')
        if 'os.remove' in source_code or 'shutil.rmtree' in source_code:
            analysis['operations'].append('delete')
        
        # === DETECT BLOCKING CODE ===
        if 'while True:' in source_code:
            analysis['has_blocking_code'] = True
            analysis['issues'].append('infinite_loop')
        
        if 'listener.join()' in source_code:
            analysis['has_blocking_code'] = True
            analysis['issues'].append('blocking_listener')
            
            # Try to detect timeout
            if 'timeout=' in source_code:
                match = re.search(r'timeout=(\d+)', source_code)
                if match:
                    analysis['blocking_duration'] = int(match.group(1))
        
        return analysis
    
    @staticmethod
    def build_dependency_graph(analyses: List[Dict]) -> Dict[str, Any]:
        """Build dependency graph by matching ANY keys"""
        
        graph = {
            'nodes': {a['id']: a for a in analyses},
            'edges': [],
            'layers': []
        }
        
        # === MATCH INPUT ↔ OUTPUT KEYS ===
        for consumer in analyses:
            if not consumer['needs_input']:
                continue
            
            consumer_id = consumer['id']
            needed_keys = consumer['input_keys']
            
            if not needed_keys:
                # Task needs input but doesn't specify keys
                # Find first independent task
                for provider in analyses:
                    if provider['is_independent'] and provider['id'] != consumer_id:
                        graph['edges'].append({
                            'from': provider['id'],
                            'to': consumer_id,
                            'keys': ['_raw_output_'],
                            'mapping': 'raw'
                        })
                        break
            else:
                # Match specific keys
                for provider in analyses:
                    if provider['id'] == consumer_id:
                        continue
                    
                    provided_keys = provider['output_keys']
                    
                    if not provided_keys:
                        if provider['is_independent']:
                            graph['edges'].append({
                                'from': provider['id'],
                                'to': consumer_id,
                                'keys': list(needed_keys),
                                'mapping': 'assume'
                            })
                    else:
                        matched = needed_keys & provided_keys
                        
                        if matched:
                            graph['edges'].append({
                                'from': provider['id'],
                                'to': consumer_id,
                                'keys': list(matched),
                                'mapping': 'exact'
                            })
        
        # === TOPOLOGICAL SORT ===
        in_degree = {nid: 0 for nid in graph['nodes']}
        for edge in graph['edges']:
            in_degree[edge['to']] += 1
        
        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        layers = []
        
        while queue:
            queue.sort(key=lambda x: int(x))
            current_layer = queue[:]
            layers.append(current_layer)
            queue = []
            
            for node in current_layer:
                for edge in graph['edges']:
                    if edge['from'] == node:
                        in_degree[edge['to']] -= 1
                        if in_degree[edge['to']] == 0:
                            if edge['to'] not in queue:
                                queue.append(edge['to'])
        
        graph['layers'] = layers
        
        return graph


class CodeReviewer:
    """
    Tự động review code đã generate
    """
    
    def __init__(self, client: OpenAI, model: str):
        self.client = client
        self.model = model
    
    def review_code(self, code: str, context: Dict) -> Dict[str, Any]:
        """
        Review code và detect issues
        """
        
        print("\n" + "="*70)
        print("SELF-REVIEW (Automated Code Review)")
        print("="*70)
        
        review_result = {
            'syntax_valid': False,
            'logic_issues': [],
            'data_flow_issues': [],
            'security_issues': [],
            'performance_issues': [],
            'suggestions': [],
            'severity': 'none'  # none, low, medium, high, critical
        }
        
        # === 1. SYNTAX CHECK ===
        print("\n🔍 Syntax validation...")
        try:
            tree = ast.parse(code)
            review_result['syntax_valid'] = True
            print("  ✅ Syntax valid")
        except SyntaxError as e:
            review_result['logic_issues'].append(f"Syntax error at line {e.lineno}: {e.msg}")
            review_result['severity'] = 'critical'
            print(f"  ❌ Syntax error at line {e.lineno}")
            return review_result
        
        # === 2. STRUCTURE CHECK ===
        print("\n🔍 Structure validation...")
        
        has_main = False
        task_functions = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if node.name == 'main':
                    has_main = True
                elif node.name.startswith('task_'):
                    task_functions.append(node.name)
        
        if not has_main:
            review_result['logic_issues'].append("Missing main() function")
            review_result['severity'] = 'critical'
            print("  ❌ Missing main() function")
        else:
            print(f"  ✅ main() function found")
        
        print(f"  ✅ Found {len(task_functions)} task functions")
        
        # === 3. DATA FLOW ANALYSIS ===
        print("\n🔍 Data flow analysis...")
        
        source_lines = code.split('\n')
        
        # Check for common data flow issues
        issues_found = 0
        
        # Issue 1: Blocking code without timeout
        if 'listener.join()' in code and 'timeout=' not in code:
            review_result['logic_issues'].append("Blocking listener.join() without timeout")
            review_result['severity'] = max_severity(review_result['severity'], 'high')
            issues_found += 1
            print("  ⚠️  Blocking listener without timeout")
        
        # Issue 2: Infinite loop
        if 'while True:' in code and 'break' not in code:
            review_result['performance_issues'].append("Infinite loop without break condition")
            review_result['severity'] = max_severity(review_result['severity'], 'medium')
            issues_found += 1
            print("  ⚠️  Infinite loop detected")
        
        # Issue 3: Writing plaintext before encryption
        encrypt_line = None
        write_line = None
        
        for i, line in enumerate(source_lines):
            if 'encrypt' in line.lower() or 'AES' in line or 'cipher' in line.lower():
                encrypt_line = i
            if 'open(' in line and ('w' in line or 'a' in line):
                if write_line is None:
                    write_line = i
        
        if write_line is not None and encrypt_line is not None and write_line < encrypt_line:
            review_result['security_issues'].append("File write before encryption - data may be exposed")
            review_result['severity'] = max_severity(review_result['severity'], 'high')
            issues_found += 1
            print("  ❌ Security: Writing before encryption!")
        
        # Issue 4: Key management
        if 'get_random_bytes' in code and 'return' in code:
            # Check if random key is returned
            if re.search(r"'key':\s*\w+", code):
                review_result['security_issues'].append("Random encryption key returned - cannot decrypt later")
                review_result['severity'] = max_severity(review_result['severity'], 'high')
                issues_found += 1
                print("  ❌ Security: Random key management issue!")
        
        if issues_found == 0:
            print("  ✅ No critical data flow issues")
        
        # === 4. LLM-BASED DEEP REVIEW ===
        print("\n🔍 LLM deep review...")
        
        system_prompt = """You are an expert code reviewer specializing in security and correctness.

Review this Python malware code and identify:
1. Logic errors in execution flow
2. Data flow issues (wrong data passed between functions)
3. Security vulnerabilities
4. Performance problems

Respond in JSON format:
{
  "logic_issues": ["issue1", "issue2"],
  "data_flow_issues": ["issue1"],
  "security_issues": ["issue1"],
  "performance_issues": ["issue1"],
  "suggestions": ["suggestion1"],
  "severity": "none|low|medium|high|critical"
}
"""
        
        user_prompt = f"""Review this code:

CONTEXT:
- Tasks: {context.get('task_count', 0)}
- Independent tasks: {context.get('independent_count', 0)}
- Pipeline stages: {context.get('pipeline_count', 0)}

CODE:
```python
{code[:8000]}  # First 8000 chars
```

Provide detailed review in JSON format."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=1500
            )
            
            llm_review = json.loads(response.choices[0].message.content)
            
            # Merge LLM findings
            review_result['logic_issues'].extend(llm_review.get('logic_issues', []))
            review_result['data_flow_issues'].extend(llm_review.get('data_flow_issues', []))
            review_result['security_issues'].extend(llm_review.get('security_issues', []))
            review_result['performance_issues'].extend(llm_review.get('performance_issues', []))
            review_result['suggestions'].extend(llm_review.get('suggestions', []))
            
            llm_severity = llm_review.get('severity', 'none')
            review_result['severity'] = max_severity(review_result['severity'], llm_severity)
            
            print(f"  ✅ LLM review complete")
            
        except Exception as e:
            print(f"  ⚠️  LLM review failed: {e}")
        
        # === SUMMARY ===
        print("\n📋 Review Summary:")
        print(f"  • Severity: {review_result['severity'].upper()}")
        print(f"  • Logic issues: {len(review_result['logic_issues'])}")
        print(f"  • Data flow issues: {len(review_result['data_flow_issues'])}")
        print(f"  • Security issues: {len(review_result['security_issues'])}")
        print(f"  • Performance issues: {len(review_result['performance_issues'])}")
        
        if review_result['logic_issues']:
            print("\n  ❌ Logic Issues:")
            for issue in review_result['logic_issues'][:3]:
                print(f"    • {issue}")
        
        if review_result['data_flow_issues']:
            print("\n  ⚠️  Data Flow Issues:")
            for issue in review_result['data_flow_issues'][:3]:
                print(f"    • {issue}")
        
        if review_result['security_issues']:
            print("\n  🔒 Security Issues:")
            for issue in review_result['security_issues'][:3]:
                print(f"    • {issue}")
        
        return review_result
    
    def auto_fix(self, code: str, review: Dict) -> Optional[str]:
        """
        Tự động fix issues nếu có thể
        """
        
        if review['severity'] not in ['high', 'critical']:
            return None
        
        print("\n" + "="*70)
        print("AUTO-FIX (Attempting to fix critical issues)")
        print("="*70)
        
        all_issues = (
            review.get('logic_issues', []) +
            review.get('data_flow_issues', []) +
            review.get('security_issues', [])
        )
        
        if not all_issues:
            return None
        
        system_prompt = """You are an expert Python developer fixing malware code issues.

Fix the following issues in the code:
{issues}

RULES:
1. Fix ONLY the identified issues
2. Do NOT change overall structure
3. Maintain all functionality
4. Output ONLY the fixed Python code, no markdown

Focus on:
- Adding timeouts to blocking calls
- Fixing data flow (correct variable passing)
- Fixing encryption flow (encrypt BEFORE write)
- Fixing key management

Output complete fixed code."""
        
        issues_text = "\n".join([f"- {issue}" for issue in all_issues[:5]])
        system_prompt = system_prompt.format(issues=issues_text)
        
        user_prompt = f"""Fix this code:
```python
{code}
```

Apply these fixes:
{issues_text}
"""
        
        try:
            print("  🤖 Calling LLM to fix issues...")
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=6000
            )
            
            fixed_code = response.choices[0].message.content.strip()
            
            # Clean markdown
            fixed_code = re.sub(r'^```[a-z]*\n', '', fixed_code)
            fixed_code = re.sub(r'\n```$', '', fixed_code)
            
            # Validate syntax
            try:
                ast.parse(fixed_code)
                print("  ✅ Auto-fix successful")
                return fixed_code
            except:
                print("  ❌ Auto-fix produced invalid syntax")
                return None
        
        except Exception as e:
            print(f"  ❌ Auto-fix failed: {e}")
            return None


def max_severity(current: str, new: str) -> str:
    """Return maximum severity"""
    levels = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    current_level = levels.get(current, 0)
    new_level = levels.get(new, 0)
    
    for sev, level in levels.items():
        if level == max(current_level, new_level):
            return sev
    return 'none'


class UniversalIntegrationAgent:
    """
    100% Universal Integration với Self-Review
    """
    
    def __init__(self) -> None:
        load_dotenv()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.client = OpenAI()
        self.max_retries = 3
        self.analyzer = UniversalCodeAnalyzer()
        self.reviewer = CodeReviewer(self.client, self.model)
    
    def _call_llm(self, system: str, user: str) -> str:
        for attempt in range(self.max_retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ],
                    temperature=0.05,
                    max_tokens=6000
                )
                return resp.choices[0].message.content or ""
            except RateLimitError:
                if attempt == self.max_retries - 1:
                    raise
                wait = 10 * (attempt + 1)
                print(f"⏳ Rate limit, waiting {wait}s...")
                time.sleep(wait)
        raise Exception("Max retries exceeded")
    
    def _fix_blocking_code(self, code: str, analysis: Dict) -> str:
        """Fix blocking code"""
        
        if not analysis.get('has_blocking_code'):
            return code
        
        print(f"  🔧 Fixing blocking code in task {analysis['id']}")
        
        system = (
            "Fix blocking code in Python function.\n\n"
            "ISSUES TO FIX:\n"
            "- Remove 'while True' loops → do limited iterations or single run\n"
            "- Fix 'listener.join()' → add timeout parameter\n"
            "- Keep all other logic unchanged\n\n"
            "Output ONLY the fixed code, no markdown."
        )
        
        user = f"Fix this code:\n\n{code}"
        
        fixed = self._call_llm(system, user)
        fixed = re.sub(r'^```[a-z]*\n', '', fixed.strip())
        fixed = re.sub(r'\n```$', '', fixed.strip())
        
        return fixed
    
    def _generate_universal_orchestration(self, graph: Dict, analyses_map: Dict) -> str:
        """Generate orchestration - works for ANY keys"""
        
        lines = [
            "def main():",
            "    '''Universal orchestration (auto-generated)'''",
            "    state = {'outputs': {}, 'results': {}, 'success': True}",
            "    ",
        ]
        
        for layer_idx, layer in enumerate(graph['layers'], 1):
            if len(layer) > 1:
                lines.append(f"    # === Layer {layer_idx}: {len(layer)} tasks ===")
            else:
                lines.append(f"    # === Layer {layer_idx} ===")
            lines.append("    ")
            
            for task_id in layer:
                analysis = analyses_map[task_id]
                task_type = analysis['type'].replace('-', '_')
                task_name = analysis['name']
                
                # Find dependencies
                deps = [e for e in graph['edges'] if e['to'] == task_id]
                
                if not deps:
                    input_expr = "None"
                    comment = "Independent task"
                else:
                    dep = deps[0]
                    dep_id = dep['from']
                    mapping_type = dep.get('mapping', 'exact')
                    keys = dep['keys']
                    
                    if mapping_type == 'raw' or '_raw_output_' in keys:
                        input_expr = f"state['outputs'].get('{dep_id}')"
                        comment = f"Uses raw output from task {dep_id}"
                    
                    elif mapping_type == 'exact' and len(keys) == 1:
                        key = keys[0]
                        consumer_keys = analysis['input_keys']
                        
                        if key in consumer_keys:
                            input_expr = f"{{'{key}': state['outputs'].get('{dep_id}', {{}}).get('{key}')}}"
                            comment = f"Needs '{key}' from task {dep_id}"
                        else:
                            input_expr = f"state['outputs'].get('{dep_id}')"
                            comment = f"Uses output from task {dep_id}"
                    
                    elif mapping_type == 'assume':
                        consumer_keys = list(analysis['input_keys'])
                        
                        if len(consumer_keys) == 1:
                            key = consumer_keys[0]
                            input_expr = f"{{'{key}': state['outputs'].get('{dep_id}')}}"
                            comment = f"Wraps task {dep_id} output as '{key}'"
                        else:
                            input_expr = f"state['outputs'].get('{dep_id}', {{}})"
                            comment = f"Uses task {dep_id} output (multi-key)"
                    
                    else:
                        if len(deps) == 1:
                            input_expr = f"state['outputs'].get('{dep_id}', {{}})"
                            comment = f"Uses task {dep_id} output"
                        else:
                            dep_ids = [d['from'] for d in deps]
                            parts = [f"**state['outputs'].get('{did}', {{}})" for did in dep_ids]
                            input_expr = "{" + ", ".join(parts) + "}"
                            comment = f"Merges from tasks {', '.join(dep_ids)}"
                
                lines.extend([
                    f"    # Task {task_id}: {task_name}",
                    f"    # {comment}",
                    f"    try:",
                    f"        r{task_id} = task_{task_id}_{task_type}({input_expr})",
                    f"        state['results']['{task_id}'] = r{task_id}",
                    f"        ",
                    f"        if r{task_id}.get('success'):",
                    f"            output = r{task_id}.get('data')",
                    f"            if output is not None:",
                    f"                state['outputs']['{task_id}'] = output",
                    f"            print(f'[+] Task {task_id}: {task_name} - OK')",
                    f"        else:",
                    f"            error = r{task_id}.get('error', 'Unknown')",
                    f"            print(f'[!] Task {task_id}: {task_name} - FAILED: {{error}}')",
                    f"            state['success'] = False",
                    f"    except Exception as e:",
                    f"        print(f'[!] Task {task_id}: {task_name} - CRASHED: {{e}}')",
                    f"        state['results']['{task_id}'] = {{'success': False, 'error': str(e)}}",
                    f"        state['success'] = False",
                    f"    ",
                ])
        
        lines.extend([
            "    if state['success']:",
            "        print('[+] All tasks completed successfully')",
            "    else:",
            "        print('[!] Some tasks failed')",
            "    ",
            "    return state",
            ""
        ])
        
        return "\n".join(lines)
    
    def integrate(self, dev_result_path: str) -> Dict[str, Any]:
        """Universal integration với self-review"""
        
        print("\n" + "="*80)
        print("UNIVERSAL INTEGRATION AGENT v2.0 (With Self-Review)")
        print("="*80)
        
        with open(dev_result_path, 'r') as f:
            dev_result = json.load(f)
        
        modules = dev_result.get('modules', [])
        valid_modules = [m for m in modules if m.get('status') == 'success' and m.get('path')]
        
        print(f"\n📦 Modules: {len(valid_modules)}")
        
        # === STEP 1: ANALYZE ===
        print("\n" + "="*70)
        print("STEP 1: CODE ANALYSIS")
        print("="*70)
        
        analyses = []
        module_codes = {}
        
        for module in valid_modules:
            task_id = module['id']
            
            try:
                code = Path(module['path']).read_text(encoding='utf-8')
                module_codes[task_id] = code
                
                analysis = self.analyzer.analyze_module(code, module)
                analyses.append(analysis)
                
                print(f"\n📝 Task {task_id}: {module['name']}")
                print(f"  • Type: {module['type']}")
                print(f"  • Independent: {analysis['is_independent']}")
                
                if analysis['data_sources']:
                    print(f"  • Data sources: {', '.join(analysis['data_sources'][:2])}")
                
                if analysis['input_keys']:
                    print(f"  • Expects input: {list(analysis['input_keys'])}")
                else:
                    print(f"  • Input: Generic/None")
                
                if analysis['output_keys']:
                    print(f"  • Outputs: {list(analysis['output_keys'])}")
                
                if analysis['operations']:
                    print(f"  • Operations: {', '.join(analysis['operations'])}")
                
                if analysis['issues']:
                    print(f"  ⚠️  Issues: {', '.join(analysis['issues'])}")
                
            except Exception as e:
                print(f"  ✗ Failed: {e}")
        
        # === STEP 2: FIX BLOCKING CODE ===
        print("\n" + "="*70)
        print("STEP 2: AUTO-FIX BLOCKING CODE")
        print("="*70)
        
        fixed_codes = {}
        fix_count = 0
        
        for analysis in analyses:
            task_id = analysis['id']
            code = module_codes[task_id]
            
            if analysis.get('has_blocking_code'):
                fixed_code = self._fix_blocking_code(code, analysis)
                fixed_codes[task_id] = fixed_code
                fix_count += 1
                print(f"  ✓ Fixed task {task_id}")
            else:
                fixed_codes[task_id] = code
        
        print(f"\n  • Auto-fixed: {fix_count} modules")
        
        # === STEP 3: BUILD DEPENDENCY GRAPH ===
        print("\n" + "="*70)
        print("STEP 3: DEPENDENCY GRAPH")
        print("="*70)
        
        graph = self.analyzer.build_dependency_graph(analyses)
        
        print(f"\n📊 Graph Stats:")
        print(f"  • Nodes (tasks): {len(graph['nodes'])}")
        print(f"  • Edges (dependencies): {len(graph['edges'])}")
        print(f"  • Execution layers: {len(graph['layers'])}")
        
        if graph['edges']:
            print(f"\n  Data Flow:")
            for edge in graph['edges']:
                keys = edge['keys']
                mapping = edge.get('mapping', 'exact')
                
                if '_raw_output_' in keys:
                    keys_str = " (raw)"
                else:
                    keys_str = f" [{', '.join(keys)}] ({mapping})"
                
                print(f"    Task {edge['from']} → Task {edge['to']}{keys_str}")
        
        print(f"\n  Execution Order:")
        for idx, layer in enumerate(graph['layers'], 1):
            print(f"    Layer {idx}: {', '.join(layer)}")
        
        # === STEP 4: GENERATE ORCHESTRATION ===
        print("\n" + "="*70)
        print("STEP 4: GENERATE ORCHESTRATION")
        print("="*70)
        
        analyses_map = {a['id']: a for a in analyses}
        orchestration = self._generate_universal_orchestration(graph, analyses_map)
        
        print(f"  ✓ Generated main() function ({len(orchestration.splitlines())} lines)")
        
        # === STEP 5: MERGE CODE ===
        print("\n" + "="*70)
        print("STEP 5: MERGE MODULES")
        print("="*70)
        
        system = (
            "Merge Python modules into one executable script.\n\n"
            "RULES:\n"
            "1. Rename each run() function to task_<id>_<type>(input_data=None)\n"
            "2. Deduplicate imports (keep unique imports once at top)\n"
            "3. Keep ALL helper functions and classes from modules\n"
            "4. Use the EXACT main() function provided\n"
            "5. Output ONLY valid Python code, no markdown\n\n"
            f"MAIN FUNCTION TO USE:\n```python\n{orchestration}\n```"
        )
        
        module_texts = []
        for tid in sorted(fixed_codes.keys(), key=int):
            code = fixed_codes[tid]
            analysis = analyses_map[tid]
            module_texts.append(
                f"# ===== Task {tid}: {analysis['name']} ({analysis['type']}) =====\n"
                f"{code}\n"
            )
        
        user = "Merge these modules:\n\n" + "\n".join(module_texts)
        
        print(f"  🤖 Calling LLM for merging...")
        
        merged = self._call_llm(system, user)
        
        # Clean markdown
        merged = re.sub(r'^```[a-z]*\n', '', merged.strip())
        merged = re.sub(r'\n```$', '', merged.strip())
        
        if not merged.startswith("#!/usr"):
            merged = "#!/usr/bin/env python3\n# Universal malware integration\n\n" + merged
        
        print(f"  ✓ Merged code: {len(merged.splitlines())} lines")
        
        # === STEP 6: SELF-REVIEW ===
        review_context = {
            'task_count': len(analyses),
            'independent_count': len([a for a in analyses if a['is_independent']]),
            'pipeline_count': len([a for a in analyses if not a['is_independent']])
        }
        
        review = self.reviewer.review_code(merged, review_context)
        
        # === STEP 7: AUTO-FIX IF NEEDED ===
        if review['severity'] in ['high', 'critical']:
            fixed_merged = self.reviewer.auto_fix(merged, review)
            
            if fixed_merged:
                print("\n  ✅ Applied auto-fixes")
                merged = fixed_merged
                
                # Re-review
                print("\n  🔄 Re-reviewing fixed code...")
                review = self.reviewer.review_code(merged, review_context)
        
        # === STEP 8: SAVE ===
        print("\n" + "="*70)
        print("SAVING RESULTS")
        print("="*70)
        
        out_dir = Path("artifacts/integration")
        out_dir.mkdir(parents=True, exist_ok=True)
        
        output = out_dir / f"malware_universal_{_stamp()}.py"
        output.write_text(merged, encoding='utf-8')
        
        latest = out_dir / "malware_latest.py"
        latest.write_text(merged, encoding='utf-8')
        
        try:
            os.chmod(output, 0o755)
            os.chmod(latest, 0o755)
        except:
            pass
        
        # Save review report
        review_file = out_dir / f"review_{_stamp()}.json"
        review_file.write_text(json.dumps(review, indent=2), encoding='utf-8')
        
        print(f"\n💾 Files saved:")
        print(f"  • {output}")
        print(f"  • {latest}")
        print(f"  • {review_file}")
        
        # === FINAL SUMMARY ===
        print("\n" + "="*80)
        print("✅ INTEGRATION COMPLETE")
        print("="*80)
        
        print(f"\n📊 Summary:")
        print(f"  • Tasks integrated: {len(analyses)}")
        print(f"  • Auto-fixed modules: {fix_count}")
        print(f"  • Dependencies: {len(graph['edges'])}")
        print(f"  • Execution layers: {len(graph['layers'])}")
        print(f"  • Lines of code: {len(merged.splitlines())}")
        print(f"\n  Review:")
        print(f"  • Severity: {review['severity'].upper()}")
        print(f"  • Syntax: {'✅ Valid' if review['syntax_valid'] else '❌ Invalid'}")
        print(f"  • Issues found: {len(review['logic_issues']) + len(review['data_flow_issues']) + len(review['security_issues'])}")
        
        if review['severity'] in ['none', 'low']:
            print(f"\n🚀 Ready to deploy:")
            print(f"   python {latest}")
        elif review['severity'] == 'medium':
            print(f"\n⚠️  Deploy with caution - review issues first")
        else:
            print(f"\n❌ DO NOT DEPLOY - Fix critical issues first")
        
        return {
            'agent': 'universal_v2_with_review',
            'tasks': len(analyses),
            'fixed_modules': fix_count,
            'dependencies': len(graph['edges']),
            'layers': len(graph['layers']),
            'output': str(output),
            'review': review,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Universal Integration Agent v2.0 (With Self-Review)"
    )
    parser.add_argument("--dev-result", required=True, help="Path to dev result JSON")
    args = parser.parse_args()
    
    try:
        agent = UniversalIntegrationAgent()
        result = agent.integrate(args.dev_result)
        
        if result['review']['severity'] in ['none', 'low']:
            print("\n✅ SUCCESS - Code is ready!")
        elif result['review']['severity'] == 'medium':
            print("\n⚠️  CAUTION - Review warnings before deployment")
        else:
            print("\n❌ CRITICAL ISSUES - Fix before deployment")
    
    except Exception as e:
        print(f"\n💥 Integration failed: {e}")
        import traceback
        traceback.print_exc()
        import sys
        sys.exit(1)