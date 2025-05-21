#!/bin/bash

# Copy model.h5 to ddos_detection_model.h5 for the controller to use
echo "Setting up DDoS detection model..."
cd /home/garv/Desktop/Cyber-Security

# Check if model.h5 exists
if [ -f "model.h5" ]; then
  echo "Copying model.h5 to ddos_detection_model.h5"
  cp model.h5 ddos_detection_model.h5
# If not, check if model2.keras exists
elif [ -f "model2.keras" ]; then
  echo "Copying model2.keras to ddos_detection_model.h5"
  cp model2.keras ddos_detection_model.h5
else
  echo "ERROR: No model file found (neither model.h5 nor model2.keras exists)"
  exit 1
fi

echo "Model setup complete!"
