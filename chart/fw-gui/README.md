# FW-GUI Helm Chart

A Helm chart for deploying FW-GUI application with MongoDB backend on Kubernetes.

## Overview

This chart deploys:
- **fw-gui-app**: Web application container (`ibehren1/fw-gui:latest`)
- **mongodb**: Database container (`mongo:latest`)
- **Persistent storage**: For application data and MongoDB data
- **LoadBalancer service**: External access on port 80

## Prerequisites

- Kubernetes cluster
- Helm 3.x
- Storage class that supports dynamic provisioning

## Installation

```bash
# Install the chart
helm install fw-gui .

# Install with custom release name
helm install my-fw-gui .

# Upgrade existing installation
helm upgrade fw-gui .
```

## Configuration

### Key Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `LoadBalancer` |
| `service.port` | External service port | `80` |
| `containers.fw-gui-app.image.repository` | FW-GUI image repository | `ibehren1/fw-gui` |
| `containers.fw-gui-app.image.tag` | FW-GUI image tag | `latest` |
| `containers.mongodb.image.repository` | MongoDB image repository | `mongo` |
| `containers.mongodb.image.tag` | MongoDB image tag | `latest` |

### Environment Variables

The fw-gui-app container includes these environment variables:

- `APP_SECRET_KEY`: Application secret key
- `DISABLE_REGISTRATION`: Registration setting
- `SESSION_TIMEOUT`: Session timeout in minutes
- `BUCKET_NAME`: S3 bucket name (optional)
- `AWS_ACCESS_KEY_ID`: AWS access key (optional)
- `AWS_SECRET_ACCESS_KEY`: AWS secret key (optional)
- `MONGODB_URI`: MongoDB connection string

### Persistent Storage

The chart creates three PersistentVolumeClaims:

- `fw-gui-data-pvc` (1Gi): Application data at `/opt/fw-gui/data`
- `mongodb-data-pvc` (5Gi): MongoDB data at `/data/db`
- `mongodb-config-pvc` (1Gi): MongoDB config at `/data/configdb`

**Note**: PVCs are configured to persist after chart uninstallation using the `helm.sh/resource-policy: keep` annotation.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   fw-gui-app    │    │    mongodb      │
│   Port: 8080    │◄──►│   Port: 27017   │
│                 │    │                 │
│ /opt/fw-gui/data│    │ /data/db        │
│                 │    │ /data/configdb  │
└─────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐
│ LoadBalancer    │
│ Port: 80        │
└─────────────────┘
```

## Accessing the Application

After installation, get the external IP:

```bash
kubectl get service fw-gui
```

Then access the application at `http://<EXTERNAL-IP>`

## Troubleshooting

### Check pod status
```bash
kubectl get pods
kubectl describe pod <pod-name>
```

### Check logs
```bash
kubectl logs <pod-name> -c fw-gui-app
kubectl logs <pod-name> -c mongodb
```

### Check PVC status
```bash
kubectl get pvc
```

## Uninstalling

```bash
# Uninstall the chart (PVCs will be preserved)
helm uninstall fw-gui

# To also delete PVCs manually
kubectl delete pvc fw-gui-data-pvc mongodb-data-pvc mongodb-config-pvc
```

## Development

### Chart Structure
```
fw-gui-helm-chart/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── pvc.yaml
│   ├── storageclass.yaml
│   └── _helpers.tpl
└── README.md
```

### Testing
```bash
# Validate chart
helm lint .

# Dry run
helm install fw-gui . --dry-run

# Template output
helm template fw-gui .
```
