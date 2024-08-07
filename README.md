# keycloak-redirecterator

## ARCHIVED: This repo is replaced by [keycloakerator](https://github.com/statisticsnorway/keycloakerator/)

## Description

CRD and controller for managing Keycloak client redirect URIs.
Used to allow services in Kubernetes to add redirect URIs to Keycloak clients.
Example use case: An exposed service with unknown URI before launch with oauth2-proxy/reverse proxy which authenticates with Keycloak. 
E.g. the service is launched by [onyxia](https://onyxia.sh/).


Manifest example:
```yaml
apiVersion: dapla.ssb.no/v1alpha1
kind: CommonClientRedirectUri
metadata:
  name: my-service
  labels:
    app: my-service
spec:
  clientId: <keycloak-client-id>{{ .Values.security.oauth2.clientId | quote }}
  redirectUri: <the uri of the service which should be added to the redirect URI of the keycloak client. e.g. https://<serivce-url>/oauth2/callback if using oauth2-proxy>
  secretName: <name of the kubernetes secret which will be created, containing the client secret for the keycloak client. May be used be the service, e.g. oauth2proxy>
```


## Configuration

The operator needs to be configured with the following environment variables:

| Name | Description |
| ---- | ----------- |
| `KEYCLOAK_HOST` | Hostname of Keycloak instance |
| `KEYCLOAK_CLIENT_ID` | Client ID of Keycloak client used to authenticate with Keycloak |
| `KEYCLOAK_CLIENT_SECRET` | Client secret of Keycloak client used to authenticate with Keycloak |
| `KEYCLOAK_REALM` | Keycloak realm |

There are also two optional environment variables:

| Name | Description |
| ---- | ----------- |
| `KEYCLOAK_CLIENT_ID_WHITELIST` | Comma separated list of client IDs that are allowed to be specified in a CommonClientRedirectUri spec. |
| `KEYCLOAK_REDIRECT_URI_REGEX` | Regular expression used to validate the redirect URI in the spec. |

## Getting Started
You’ll need a Kubernetes cluster to run against. You can use [KIND](https://sigs.k8s.io/kind) to get a local cluster for testing, or run against a remote cluster.
**Note:** Your controller will automatically use the current context in your kubeconfig file (i.e. whatever cluster `kubectl cluster-info` shows).

### Running on the cluster
1. Install Instances of Custom Resources:

```sh
kubectl apply -k config/samples/
```

2. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/keycloak-redirecterator:tag
```

3. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/keycloak-redirecterator:tag
```

### Uninstall CRDs
To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller
UnDeploy the controller from the cluster:

```sh
make undeploy
```

## Contributing

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/).

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/),
which provide a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.

### Test It Out
1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

### Modifying the API definitions
If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)
