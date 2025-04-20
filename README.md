# DDoS Attack Detection and Mitigation System

Welcome to the **Cyber-Security** project repository! This guide will walk you through the steps to set up and run the project locally on your system, ensuring a smooth experience.

## 🛠️ Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.9** (recommended version)
- **Mininet** for network simulation
- **Ryu** for Software-Defined Networking (SDN) control

If you're new to these tools, follow the instructions below to install them.

## 🚀 Step 1: Downgrade Python to 3.9 (if necessary)

This project uses **Python 3.9**, so ensure you have it installed. If not, follow these steps:

### Install Python 3.9

```bash
sudo apt update
sudo apt install python3.9 python3.9-venv python3.9-dev
```

### Verify Installation

```bash
python3.9 --version
```

## 🧑‍💻 Step 2: Set Up Virtual Environment

Creating a virtual environment will help isolate dependencies and keep your project organized.

### Install `virtualenv`

If not already installed, run:

```bash
sudo apt install python3-venv
```

### Create a New Virtual Environment

In your project directory, run:

```bash
python3.9 -m venv ryu39-env
```

### Activate the Virtual Environment

```bash
source ryu39-env/bin/activate
```

Your terminal prompt should change to something like this:

```
(ryu39-env) ➜ Cyber-Security
```

### Install Dependencies

With the virtual environment activated, install the required dependencies:

```bash
pip install --upgrade pip
pip install setuptools==57.5.0  # Specific version of setuptools for compatibility
pip install ryu  # Install Ryu framework
```

## 🏃‍♂️ Step 3: Start the Ryu Controller

To manage the network topology with SDN, you'll need to start the Ryu controller.

1. **Open a New Terminal Window** (leave the original terminal with the virtual environment activated).
2. **Start the Ryu Controller**: Run the following command to start the Ryu controller:
```bash
ryu-manager your_controller.py
```
Replace `your_controller.py` with the name of your custom controller script (e.g., `controller.py` or any other controller you're using).

## 🔧 Step 4: Run the Project

With the virtual environment set up and the Ryu controller running, you're ready to run the project.

### Run the Mininet Topology

If you have a topology script like `topology.py`, run it using:

```bash
sudo python3 topology.py
```

This will initialize your network with the hosts and switches defined in the topology script.

### Access the Mininet CLI

Once the topology is running, the Mininet CLI will appear. You can test connectivity between hosts with commands like:

```bash
mininet> ping 10.0.0.1  # Test ping between hosts
```

Ensure that your Ryu controller is running and actively managing the switches for proper functionality.

## 🛑 Step 5: Deactivate the Virtual Environment

When you're done working on the project, deactivate the virtual environment:

```bash
deactivate
```

This will return your terminal back to the global environment.

## 🔄 Step 6: Upgrade Python and Virtual Environment (if needed)

If you need to upgrade Python or the virtual environment after working on the project, follow these steps:

### Upgrade Python Version

```bash
sudo apt install python3.x python3.x-venv python3.x-dev  # Replace 3.x with the desired version
```

### Create a New Virtual Environment

```bash
python3.x -m venv myenv  # Replace 3.x with the upgraded Python version
```

### Activate the New Environment

```bash
source myenv/bin/activate
```

### Reinstall Dependencies

```bash
pip install --upgrade pip
pip install setuptools==57.5.0
pip install ryu
```

## 💡 Additional Tips

- **Keep your environment isolated**: Always activate the virtual environment when working on the project and deactivate it when done.
- **Ensure the controller is running**: The Ryu controller must be active for the Mininet topology to function correctly.
- **Use the correct Python version**: Avoid compatibility issues by using Python 3.9 as specified for this project.
- **Experiment with Mininet**: Use the Mininet CLI to test and modify the network topology as needed.

## 🚀 Let's get started! Happy coding! 🚀