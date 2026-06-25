filepath = "src/ai_osop/core/models.py"
with open(filepath, "r") as f:
    content = f.read()

# Add lease_expires if not present
if "lease_expires: Optional[datetime] = None" not in content:
    content = content.replace("    trace_context: Dict[str, Any] = Field(default_factory=dict)\n",
                              "    trace_context: Dict[str, Any] = Field(default_factory=dict)\n    lease_expires: Optional[datetime] = None\n")

with open(filepath, "w") as f:
    f.write(content)
