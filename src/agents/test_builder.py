from builder_openai import ExecutableBuilder, BuildConfig
from datetime import datetime, timezone

def main():
    run_id = f"test_build_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    pipeline_path = "artifacts/integration/screenshot_capture_20260302_131544_166847.py"
    
    builder = ExecutableBuilder()
    
    result = builder.build(
        run_id=run_id,
        pipeline_path=pipeline_path,
        plan=None,          # optional
        modules=None        # optional
    )

    print("\n✅ Build Result:")
    for key, value in result.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    main()
