import logging

def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler("sentinel.log"), logging.StreamHandler()]
    )
    return logging.getLogger("GridCloudSentinel")
  
