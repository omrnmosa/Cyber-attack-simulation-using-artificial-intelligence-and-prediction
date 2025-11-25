"""
Analysis Logger - Handles all ML training and analysis output in a dedicated console
"""
import sys
from datetime import datetime
from pathlib import Path
import logging

# Configure logging to both file and console
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Create handlers
file_handler = logging.FileHandler(LOG_DIR / f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
console_handler = logging.StreamHandler(sys.stdout)

# Configure format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Create logger
logger = logging.getLogger('analysis')
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

def log_ml_training(metrics: dict, artifacts: dict):
    """Log ML training results with detailed metrics"""
    logger.info("=== ML Training Results ===")
    logger.info(f"Dataset Size: {metrics.get('rows', 0)} samples")
    logger.info(f"Class Balance: {metrics.get('class_balance', {})}")
    
    if 'metrics' in metrics:
        clf_metrics = metrics['metrics'].get('classification', {})
        reg_metrics = metrics['metrics'].get('regression', {})
        
        logger.info("\nClassification Metrics:")
        logger.info(f"Precision: {clf_metrics.get('precision', 0):.3f}")
        logger.info(f"Recall: {clf_metrics.get('recall', 0):.3f}")
        logger.info(f"F1 Score: {clf_metrics.get('f1', 0):.3f}")
        
        logger.info("\nRegression Metrics:")
        logger.info(f"MAE: {reg_metrics.get('mae', 0):.4f}")
        logger.info(f"R² Score: {reg_metrics.get('r2', 0):.4f}")
    
    logger.info("\nFeature Information:")
    logger.info(f"Total Features: {artifacts.get('char_features', 0)}")

def log_scan_analysis(scan_id: int, findings: list, risk: float, critical: float):
    """Log detailed scan analysis results"""
    logger.info(f"\n=== Scan {scan_id} Analysis ===")
    logger.info(f"Total Findings: {len(findings)}")
    logger.info(f"Risk Score: {risk:.2%}")
    logger.info(f"Critical Probability: {critical:.2%}")
    
    # Categorize findings
    types = {}
    severities = {}
    for f in findings:
        t = f.get('type', 'unknown')
        types[t] = types.get(t, 0) + 1
        sev = f.get('severity', 'unknown')
        severities[sev] = severities.get(sev, 0) + 1
    
    logger.info("\nFinding Types:")
    for t, count in types.items():
        logger.info(f"- {t}: {count}")
    
    logger.info("\nSeverity Distribution:")
    for sev, count in severities.items():
        logger.info(f"- {sev}: {count}")

def log_ethics_decision(url: str, decision: str, reason: str):
    """Log ethics policy decisions and reasons"""
    logger.info(f"\n=== Ethics Policy Decision ===")
    logger.info(f"Target URL: {url}")
    logger.info(f"Decision: {decision}")
    logger.info(f"Reason: {reason}")