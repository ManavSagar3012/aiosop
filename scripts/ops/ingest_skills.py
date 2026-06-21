import os
import shutil
from pathlib import Path

def ingest_skills():
    """Ingests all skills from the local agents directory into the ai-osop project."""
    source_dir = Path(r"C:\Users\HP\.agents\skills")
    dest_dir = Path("src/ai_osop/agents/skills")
    
    # Ensure destination exists
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    if not source_dir.exists():
        print(f"Source directory {source_dir} not found.")
        return

    count = 0
    for skill_folder in source_dir.iterdir():
        if skill_folder.is_dir():
            skill_name = skill_folder.name
            skill_md = skill_folder / "SKILL.md"
            
            if skill_md.exists():
                dest_file = dest_dir / f"{skill_name}.md"
                shutil.copy2(skill_md, dest_file)
                count += 1
                print(f"Ingested: {skill_name}")

    print(f"\nSuccessfully ingested {count} skills into {dest_dir}")

if __name__ == "__main__":
    ingest_skills()
