#!/usr/bin/env python3
# /// script
# dependencies = [
#   "pyyaml",
# ]
# ///
import os
import sys
import yaml

def print_status(success, message):
    prefix = "✅" if success else "❌"
    print(f"{prefix} {message}")

def validate_environment():
    # Find the path of the script (.agents/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    
    # configuration file is in the same directory as the script
    config_path = os.path.join(script_dir, "antigravity.yaml")
    
    if not os.path.exists(config_path):
        print_status(False, f"antigravity.yaml not found at expected path: {config_path}")
        sys.exit(1)
        
    print(f"Checking configuration in {config_path}...")
    print(f"Validating relative paths against project root: {project_root}\n" + "-"*40)
    
    # Change working directory to project root so that relative paths (like ./.agents/...) load correctly
    os.chdir(project_root)
    
    with open(config_path, "r", encoding="utf-8") as f:
        try:
            config = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            print_status(False, f"Coult not read YAML: {exc}")
            sys.exit(1)
            
    has_errors = False
    
    # 1. Validate workspace settings
    workspace = config.get("workspace", {})
    resources_path = workspace.get("resources_path")
    
    if resources_path:
        if os.path.exists(resources_path):
            print_status(True, f"Workspace resources found: {resources_path}")
        else:
            print_status(False, f"Workspace resources not found on expected path: {resources_path}")
            has_errors = True
    else:
        print_status(False, "workspace.resources_path not defined in yaml-file.")
        has_errors = True

    # 2. Validate all skills dynamnically
    skills = config.get("skills", [])
    if not skills:
        print_status(False, "No skills defined under 'skills:' list.")
        has_errors = True
    else:
        print(f"\nVerify {len(skills)} defined skill paths:")
        for skill_entry in skills:
            path = skill_entry.get("path")
            if not path:
                print_status(False, "Found emtpy or undefined path in the skills-list.")
                has_errors = True
                continue
                
            if os.path.exists(path):
                print_status(True, f"Skill configured OK: {path}")
            else:
                print_status(False, f"Skill FILE MISSING: {path}")
                has_errors = True
                
    # 3. End state
    print("-"*40)
    if has_errors:
        print_status(False, "Verification failed! Correct paths in .agents/antigravity.yaml.")
        sys.exit(1)
    else:
        print_status(True, "All good! .agents is properly set up!")
        sys.exit(0)

if __name__ == "__main__":
    validate_environment()
