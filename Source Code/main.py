import tkinter as tk
from gui import MetadataInspectorGUI
import logging
import os
from datetime import datetime

def setup_logging():
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f'logs/metadata_analyzer_{timestamp}.log'
    
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    return log_filename

def main():
    log_file = setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("Starting Metadata and Security Analyzer")
    logger.info(f"Log file: {log_file}")
    logger.info("=" * 60)
    
    try:
        root = tk.Tk()
        root.title("Metadata and Security Analyzer By Mueed Khan")
        root.geometry("1000x650")
        
        logger.info("Creating GUI application...")
        
        app = MetadataInspectorGUI(root)
        
        logger.info("Application initialized successfully")
        logger.info("Starting main event loop...")
        
        root.mainloop()
        
        logger.info("Application closed normally")
        
    except Exception as e:
        logger.error(f"Fatal error occurred: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
