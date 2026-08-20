import argparse
import sys
from src.intake import EvidenceIntake
from src.disk import ArtifactExtractor
from src.memory import ProcessScanner
from src.correlation import TimelineBuilder, ThreatScorer
from src.response import ReportGenerator

def run_pipeline(image_path: str, image_type: str, mount_point: str = None):
    print("=" * 60)
    print("      HYBRID MEMORY AND DISK FORENSICS FRAMEWORK      ")
    print("=" * 60)

    # 1. Evidence Intake
    intake = EvidenceIntake(file_path=image_path, image_type=image_type)
    metadata = intake.process_evidence()

    disk_artifacts = []
    memory_processes = []

    # 2. Disk Analysis
    if image_type == "disk" and mount_point:
        print("\n[*] Initializing Disk Analysis...")
        extractor = ArtifactExtractor(mount_point=mount_point)
        disk_artifacts.extend(extractor.extract_system_registry())
        disk_artifacts.extend(extractor.extract_prefetch())

    # 3. Memory Analysis
    if image_type == "memory":
        print("\n[*] Initializing Memory Analysis...")
        scanner = ProcessScanner(memory_image_path=image_path)
        memory_processes = scanner.extract_running_processes()

    # 4. Correlation Engine
    print("\n[*] Building Unified Timeline and Scoring Threats...")
    builder = TimelineBuilder()
    builder.ingest_disk_artifacts(disk_artifacts)
    builder.ingest_memory_processes(memory_processes, metadata["intake_timestamp_utc"])
    
    timeline = builder.build_timeline()
    
    scorer = ThreatScorer()
    threats = scorer.evaluate_timeline(timeline)

    # 5. Action Response & Reporting
    print("\n[*] Generating Output Reports...")
    case_id = metadata["evidence_id"]
    reporter = ReportGenerator(case_id=case_id)
    
    full_data = {
        "evidence_metadata": metadata,
        "timeline": timeline,
        "threats": threats
    }
    
    reporter.generate_json_report(full_data)
    reporter.generate_html_report(full_data)

    print("\n[+] Forensics pipeline execution finished successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid Memory & Disk Forensics CLI Tool")
    parser.add_argument("--image", required=True, help="Path to raw memory or disk image file")
    parser.add_argument("--type", required=True, choices=["disk", "memory"], help="Type of forensic image")
    parser.add_argument("--mount", required=False, help="Mount point directory for disk analysis")

    args = parser.parse_args()
    run_pipeline(image_path=args.image, image_type=args.type, mount_point=args.mount)