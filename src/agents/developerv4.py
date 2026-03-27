from __future__ import annotations
import os, json, time, ast, traceback
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI, RateLimitError

def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

class EnhancedDeveloperAgent:
    """Generate production-ready Python modules with balanced validation"""
    
    def __init__(self) -> None:
        load_dotenv()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.client = OpenAI()
        self.max_retries = 3
        
        # Only CRITICAL dangerous patterns
        self.dangerous_patterns = [
            "eval(", "exec(", "compile(", "__import__("
        ]

    def _call_llm(self, system: str, user: str) -> str:
        """Call LLM with retry on rate limits"""
        for attempt in range(self.max_retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ],
                    temperature=0.2,
                    max_tokens=2500
                )
                return resp.choices[0].message.content or ""
            except RateLimitError:
                if attempt == self.max_retries - 1:
                    raise
                wait = 5 * (attempt + 1)
                print(f"⏳ Rate limit, waiting {wait}s...")
                time.sleep(wait)
        raise Exception("Max retries exceeded")

    def _generate_code(self, subtask: Dict[str, Any], index: int) -> str:
        """Generate production-ready module with clear core logic"""
        
        system = (
            "Generate CLEAN, FOCUSED Python module.\n\n"
            
            "CORE CONTRACT:\n"
            "Must implement: def run(input_data=None) -> dict\n"
            "Return format:\n"
            "  {'success': True/False, 'data': ..., 'metadata': {'task_id': '...', 'execution_time': ...}}\n\n"
            
            "CODING PRINCIPLES:\n"
            "1. 🎯 FOCUS ON CORE LOGIC FIRST\n"
            "   - Implement the actual task clearly\n"
            "   - Use straightforward code paths\n"
            "   - Don't hide logic behind defensive checks\n\n"
            
            "2. ✅ Smart error handling (not paranoid):\n"
            "   - ONE try-except around main logic is enough\n"
            "   - Let Python's natural exceptions bubble up\n"
            "   - Only catch specific exceptions you can handle\n\n"
            
            "3. 🚫 AVOID over-defensive code:\n"
            "   ❌ NO: if lib_available: ... else: return error\n"
            "   ✅ YES: Just import and let ImportError happen naturally\n"
            "   \n"
            "   ❌ NO: Check 5 conditions before doing anything\n"
            "   ✅ YES: Do the work, catch real errors\n\n"
            
            "4. 📦 External dependencies:\n"
            "   - Assume libraries are installed (this is production env)\n"
            "   - Use subprocess.run() with timeout when needed\n"
            "   - Use requests with timeout for HTTP\n\n"
            
            "5. 🎨 Code quality:\n"
            "   - Clear variable names\n"
            "   - Logical flow (not nested if-hell)\n"
            "   - Comments for complex parts only\n\n"
            
            "REQUIRED TEMPLATE:\n"
            "#!/usr/bin/env python3\n"
            '"""Task description"""\n'
            "import sys\n"
            "import json\n"
            "import time\n"
            "from typing import Dict, Any\n"
            "# Import what you need\n\n"
            
            "def run(input_data: Dict[str, Any] = None) -> Dict[str, Any]:\n"
            "    start = time.time()\n"
            "    \n"
            "    try:\n"
            "        # ========================================\n"
            "        # CORE LOGIC HERE - Make it clear!\n"
            "        # ========================================\n"
            "        \n"
            "        result = {}\n"
            "        # ... do the actual work ...\n"
            "        \n"
            "        return {\n"
            "            'success': True,\n"
            "            'data': result,\n"
            "            'metadata': {\n"
            "                'task_id': 'TASK_ID',\n"
            "                'execution_time': time.time() - start\n"
            "            }\n"
            "        }\n"
            "        \n"
            "    except Exception as e:\n"
            "        return {\n"
            "            'success': False,\n"
            "            'error': f'{type(e).__name__}: {str(e)}',\n"
            "            'metadata': {\n"
            "                'task_id': 'TASK_ID',\n"
            "                'execution_time': time.time() - start\n"
            "            }\n"
            "        }\n\n"
            
            "if __name__ == '__main__':\n"
            "    result = run()\n"
            "    if result.get('success', False):\n"
            "        print(json.dumps(result, indent=2))\n"
            "    else:\n"
            "        print(json.dumps(result, indent=2), file=sys.stderr)\n"
            "        sys.exit(1)\n\n"
            
            "WHAT TO AVOID:\n"
            "- NO eval(), exec(), compile()\n"
            "- NO excessive input validation (trust the caller)\n"
            "- NO checking if every library is installed\n"
            "- NO nested defensive if-else chains\n\n"
            
            "Output ONLY Python code, no markdown fences."
        )
        
        task_id = subtask.get('id', f'{index}')
        name = subtask.get('name', 'Unknown')
        desc = subtask.get('desc', '')
        task_type = subtask.get('type', 'execution')
        deps = subtask.get('dependencies', [])
        
        user = (
            f"Task ID: {task_id}\n"
            f"Name: {name}\n"
            f"Type: {task_type}\n"
            f"Description: {desc}\n"
            f"Dependencies: {', '.join(deps) if deps else 'standard library'}\n\n"
            
            f"REQUIREMENTS:\n"
            f"1. Replace 'TASK_ID' with '{task_id}'\n"
            f"2. Write CLEAR core logic - this is the most important part!\n"
            f"3. Use ONE try-except block around main logic\n"
            f"4. Include __main__ block for standalone testing\n"
            f"5. Timeouts for network/subprocess (but don't over-validate)\n"
            f"6. Type hints for clarity\n"
            f"7. Make the code readable, not defensive-paranoid\n\n"
            
            f"Generate clean, focused code that DOES THE JOB."
        )
        
        code = self._call_llm(system, user).strip()
        
        # Clean markdown
        code = code.replace("```python", "").replace("```", "").strip()
        
        # Check refusal
        refusals = ["i'm sorry", "i can't", "i apologize", "i'm unable", "i cannot"]
        if any(r in code[:200].lower() for r in refusals) or len(code) < 100:
            print("⚠️ LLM refused, using fallback")
            code = self._fallback(subtask)
        
        # Ensure shebang + docstring
        if not code.startswith("#!/usr"):
            code = f"#!/usr/bin/env python3\n\"\"\"{name}\"\"\"\n\n{code}"
        
        return code

    def _validate_code(self, code: str, task_id: str, filepath: Path) -> Tuple[bool, List[str], Dict[str, Any]]:
        """Balanced validation - catch real issues, not style preferences"""
        issues = []
        warnings = []
        metrics = {}
        
        # 1. Syntax check - REQUIRED
        try:
            compile(code, str(filepath), 'exec')
            metrics['syntax_valid'] = True
        except SyntaxError as e:
            issues.append(f"Syntax error at line {e.lineno}: {e.msg}")
            metrics['syntax_valid'] = False
            return False, issues, metrics
        
        # 2. Contract check - REQUIRED
        try:
            tree = ast.parse(code)
            has_run_func = False
            has_main_block = False
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "run":
                    has_run_func = True
                if isinstance(node, ast.If):
                    # Check for if __name__ == '__main__'
                    if isinstance(node.test, ast.Compare):
                        if any(isinstance(n, ast.Name) and n.id == '__name__' 
                               for n in ast.walk(node.test)):
                            has_main_block = True
            
            if not has_run_func:
                issues.append("Missing run() function")
            
            if not has_main_block:
                warnings.append("Missing __main__ block (recommended for testing)")
            
            metrics['has_run_function'] = has_run_func
            metrics['has_main_block'] = has_main_block
        except Exception as e:
            issues.append(f"AST parse error: {e}")
        
        # 3. Return format check - REQUIRED
        if "'success'" not in code and '"success"' not in code:
            issues.append("Missing 'success' in return dict")
        
        if "return {" not in code:
            issues.append("No dict return found")
        
        # 4. Critical anti-patterns ONLY - REQUIRED
        for pattern in self.dangerous_patterns:
            if pattern in code:
                issues.append(f"CRITICAL: Dangerous pattern {pattern}")
        
        # 5. Quality metrics - FOR STATISTICS ONLY, not failures
        metrics.update({
            'lines_of_code': len(code.splitlines()),
            'has_docstring': '"""' in code[:200] or "'''" in code[:200],
            'has_try_except': 'try:' in code and 'except' in code,
            'imports_count': code.count('import '),
            'has_type_hints': '->' in code or ': Dict' in code or ': Any' in code,
            'has_timeout': 'timeout=' in code
        })
        
        # 6. Warnings only - DO NOT FAIL
        if "print(" in code and "__main__" not in code:
            warnings.append(f"Contains {code.count('print(')} print() outside __main__")
        
        if "sys.exit" in code and "__main__" not in code:
            warnings.append("Contains sys.exit() outside __main__")
        
        # 7. Quality score based on CRITICAL issues only
        score = 10
        score -= len(issues) * 3  # Only critical issues reduce score
        
        # Bonus for good practices
        if has_main_block:
            score += 1
        if metrics.get('has_type_hints'):
            score += 1
        if metrics.get('has_timeout'):
            score += 1
            
        metrics['quality_score'] = max(0, min(10, score))
        
        # PASS if no critical issues (warnings don't fail)
        return len(issues) == 0, issues + warnings, metrics

    def _fallback(self, subtask: Dict[str, Any]) -> str:
        """Clean fallback stub"""
        task_id = subtask.get('id', 'unknown')
        name = subtask.get('name', 'Task')
        task_type = subtask.get('type', 'execution')
        
        return f'''#!/usr/bin/env python3
"""{name} (Fallback Stub)"""
import sys
import json
import time
from typing import Dict, Any

def run(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Fallback implementation for {name}"""
    start = time.time()
    
    try:
        result = {{
            'task': '{name}',
            'type': '{task_type}',
            'status': 'stub_executed',
            'note': 'This is a fallback stub - implement proper logic'
        }}
        
        return {{
            'success': True,
            'data': result,
            'metadata': {{
                'task_id': '{task_id}',
                'execution_time': time.time() - start,
                'is_stub': True
            }}
        }}
    except Exception as e:
        return {{
            'success': False,
            'error': f'{{type(e).__name__}}: {{str(e)}}',
            'metadata': {{
                'task_id': '{task_id}',
                'execution_time': time.time() - start
            }}
        }}

if __name__ == '__main__':
    result = run()
    if result.get('success', False):
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result, indent=2), file=sys.stderr)
        sys.exit(1)
'''

    def develop(self, plan_path: str) -> Dict[str, Any]:
        """Generate validated production-ready modules"""
        
        # Load plan
        with open(plan_path, "r") as f:
            plan = json.load(f)
        
        subtasks = plan.get("subtasks", [])
        if not subtasks:
            raise ValueError("No subtasks in plan file")
        
        print(f"\n{'='*70}")
        print(f"CLEAN CODE GENERATION - {len(subtasks)} MODULES")
        print(f"{'='*70}\n")
        
        out_dir = Path("artifacts/modules")
        out_dir.mkdir(parents=True, exist_ok=True)
        
        modules = []
        success_count = 0
        validation_failures = []
        
        for idx, subtask in enumerate(subtasks, 1):
            name = subtask.get('name', f'task_{idx}')
            task_id = subtask.get('id', str(idx))
            task_type = subtask.get('type', 'execution')
            
            print(f"[{idx}/{len(subtasks)}] {name}...", end=" ")
            
            try:
                # Generate code
                code = self._generate_code(subtask, idx)
                
                # Create filename
                safe_name = name.lower().replace(" ", "_").replace("-", "_")
                safe_name = "".join(c for c in safe_name if c.isalnum() or c == "_")
                
                stack = os.getenv("AGENT_STACK", "openai")
                prefix_parts = [stack, "dev", f"{idx:02d}", _stamp()]
                prefix = "_".join(prefix_parts)
                
                filename = f"{prefix}_{task_type}_{safe_name}.py"
                filepath = out_dir / filename
                
                # VALIDATE before save
                is_valid, all_messages, metrics = self._validate_code(code, task_id, filepath)
                
                # Separate issues (critical) from warnings
                issues = [m for m in all_messages if "CRITICAL" in m or "Missing run()" in m or "Syntax" in m or "AST" in m or "No dict return" in m]
                warnings = [m for m in all_messages if m not in issues]
                
                if not is_valid:
                    print(f"❌ VALIDATION FAILED")
                    for issue in issues[:3]:
                        print(f"     └─ {issue}")
                    
                    validation_failures.append({
                        "task": name,
                        "issues": issues,
                        "code_preview": code[:200]
                    })
                    
                    modules.append({
                        "id": task_id,
                        "name": name,
                        "type": task_type,
                        "status": "validation_failed",
                        "issues": issues,
                        "metrics": metrics
                    })
                    continue
                
                # Save validated code
                filepath.write_text(code, encoding="utf-8")
                os.chmod(filepath, 0o755)
                
                quality = metrics.get('quality_score', 0)
                loc = metrics.get('lines_of_code', 0)
                has_main = "✓" if metrics.get('has_main_block') else "✗"
                print(f"✅ Q:{quality:.1f}/10 | {loc}L | __main__:{has_main}")
                
                if warnings:
                    print(f"     ⚠️ {len(warnings)} warning(s): {warnings[0][:50]}...")
                
                modules.append({
                    "id": task_id,
                    "name": name,
                    "type": task_type,
                    "path": str(filepath),
                    "status": "success",
                    "metrics": metrics,
                    "warnings": warnings
                })
                success_count += 1
                
            except Exception as e:
                print(f"❌ EXCEPTION: {e}")
                modules.append({
                    "id": task_id,
                    "name": name,
                    "error": str(e),
                    "traceback": traceback.format_exc()[-500:],
                    "status": "error"
                })
        
        # Summary
        print(f"\n{'='*70}")
        print(f"✅ Success: {success_count}/{len(subtasks)} "
              f"({success_count/len(subtasks)*100:.0f}%)")
        
        if validation_failures:
            print(f"❌ Validation Failures: {len(validation_failures)}")
            for fail in validation_failures[:3]:
                print(f"   • {fail['task']}: {fail['issues'][0]}")
        
        # Quality metrics
        valid_metrics = [m for m in modules if m.get('metrics')]
        if valid_metrics:
            avg_quality = sum(m['metrics']['quality_score'] for m in valid_metrics) / len(valid_metrics)
            avg_loc = sum(m['metrics']['lines_of_code'] for m in valid_metrics) / len(valid_metrics)
            with_main = sum(1 for m in valid_metrics if m['metrics'].get('has_main_block'))
            with_type_hints = sum(1 for m in valid_metrics if m['metrics'].get('has_type_hints'))
            with_timeout = sum(1 for m in valid_metrics if m['metrics'].get('has_timeout'))
            
            print(f"\n📊 Metrics:")
            print(f"   • Avg Quality Score: {avg_quality:.1f}/10")
            print(f"   • Avg Lines of Code: {avg_loc:.0f}")
            print(f"   • With __main__: {with_main}/{len(valid_metrics)}")
            print(f"   • With Type Hints: {with_type_hints}/{len(valid_metrics)}")
            print(f"   • With Timeouts: {with_timeout}/{len(valid_metrics)}")
        
        print(f"{'='*70}\n")
        
        result = {
            "agent": "enhanced_developer",
            "version": "3.1_fixed",
            "modules": modules,
            "total": len(subtasks),
            "successful": success_count,
            "failed": len(subtasks) - success_count,
            "validation_failures": validation_failures,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Save result
        result_file = out_dir / f"result_{_stamp()}.json"
        result_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"📄 Result: {result_file}")
        
        return result


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced Developer Agent - Clean Code Generation"
    )
    parser.add_argument("--plan", required=True, help="Path to planner JSON")
    args = parser.parse_args()
    
    agent = EnhancedDeveloperAgent()
    result = agent.develop(args.plan)
    
    print(f"\n📁 Modules: artifacts/modules/")
    print(f"✓ Clean, focused code with __main__ blocks")
    print(f"✓ Balanced validation (critical issues only)")
    print(f"✓ Quality metrics + testability")