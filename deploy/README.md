# Deploy Folder

The `deploy` folder contains all the necessary files and configurations for deploying the application using Helm.

## Folder Structure

- `charts/`
- `config/`
- `instances/` (optional)

### charts

The `charts` folder is where the Helm charts are placed. Helm charts are used to define, install, and upgrade Kubernetes applications. This folder contains all the Helm charts required for deploying your applications.

### config

The `config` folder contains environment-specific configuration files:

```
config/
├── dev.yaml
├── instance-1/
│   ├── dev.yaml
└── instance-2/
    ├── dev.yaml
```

Each of these files holds the config for their respective environments. These files contain the configuration values that are used by the Helm charts during deployment.

By organizing the configuration files in this manner, it becomes easier to manage and deploy the application across different environments.

### instances

The `instances` folder is optional and is used to store configuration files for different instances of the application. Each env folder contains instance-specific configuration files:

```plaintext
instances/
├── dev/
│   ├── instance1.yaml
│   ├── instance2.yaml
│   └── instance3.yaml
└── stage/
    ├── instance1.yaml
    ├── instance2.yaml
    └── instance3.yaml
```
