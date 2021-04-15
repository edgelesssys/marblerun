#!/bin/bash

function wait_for_resource() {
    grace=2

    while true; do
        eval $1 > /dev/null
        if [ $? -eq 0 ]; then
            sleep 5
            grace=2
            continue
        fi

        if [ $grace -gt 0 ]; then
            sleep 1
            grace=$(($grace-1))
            continue
        fi
        break
    done
}

function cleanup_cluster() {
    marblerun uninstall
    marblerun namespace remove default
    pkill -P $$
}


#-------------install marblerun on the cluster-----------------------

echo "Starting integration test"
if [[ -z $(kubectl get nodes | grep Ready) ]];
then
    echo "Unable to connect to cluster"
    exit 1
fi

resource_key="some.sgx.provider/epc"

marblerun install --simulation --resource-key=$resource_key
wait_for_resource "kubectl get pods -n marblerun | grep marble | grep -v Running"

marblerun namespace add default --no-sgx-injection
if [[ $(kubectl describe namespace default | grep marblerun/inject | grep -v enabled | xargs) != "marblerun/inject-sgx=disabled" ]];
then
    echo "failed to inject correct values into namespace"
    cleanup_cluster
    exit 1
fi


#-------------test setting manifest----------------------------------

echo ""
kubectl -n marblerun port-forward svc/coordinator-client-api 4433:4433 --address localhost >/dev/null &
sleep 2
echo -n "Checking coordinator state: "
if [[ $(marblerun status localhost:4433 --insecure | tail -n 1) != "2: Coordinator is ready to accept a manifest." ]]
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Setting manifest: "
if [[ $(marblerun manifest set test-manifest.json localhost:4433 --insecure | tail -n 1) != "Manifest successfully set" ]]
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Verifying set manifest: "
if [[ $(marblerun manifest get localhost:4433 --insecure | tail -n 1 | cut -d ' ' -f3) != $(marblerun manifest signature test-manifest.json) ]]
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

kubectl create -f hello-marble.yaml
wait_for_resource "kubectl get pods -n default | grep hello-marble | grep -v Running"
kubectl port-forward svc/hello-marble 8080:8080 --address localhost >/dev/null &
sleep 2

echo -n "Checking if hello-marble is running correctly: "
if [[ $(curl http://localhost:8080 -s | tail -n 1) != "Commandline arguments: [foo bar]" ]]
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"


#-------------test injection of env variables------------------------

echo ""
if [[ -n $(kubectl logs -n marblerun -l app.kubernetes.io/name=marble-injector | grep "injecting sgx tolerations") ]];
then
    echo "called the wrong webhook"
    cleanup_cluster
    exit 1
fi

echo -n "Checking env variable EDG_COORDINATOR_ADDR: "
if [[ -n $(kubectl get pod -l marblerun/marbletype=hello-world -o jsonpath='{.spec.containers[0].env[0]}' | grep -v coordinator-mesh-api.marblerun:2001) ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking env variable EDG_MARBLE_TYPE: "
if [[ -n $(kubectl get pod -l marblerun/marbletype=hello-world -o jsonpath='{.spec.containers[0].env[1]}' | grep -v test) ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking env variable EDG_MARBLE_DNS_NAMES: "
if [[ -n $(kubectl get pod -l marblerun/marbletype=hello-world -o jsonpath='{.spec.containers[0].env[2]}' | grep -v test,test.default,test.default.svc.cluster.local) ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking env variable EDG_MARBLE_UUID_FILE: "
if [[ -n $(kubectl get pod -l marblerun/marbletype=hello-world -o jsonpath='{.spec.containers[0].env[3]}' | grep -v "/test-uid/uuid-file") ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking pod resource limits: "
if [[ -n $(kubectl get pod -l marblerun/marbletype=hello-world -o jsonpath='{.spec.containers[0].resources.limits}' | grep $resource_key) ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"


#-------------test injection of sgx values---------------------------

echo ""
marblerun namespace add default

if [[ -n $(kubectl describe namespace default | grep marblerun/inject | grep -v enabled) ]];
then
    echo "failed to inject correct values into namespace"
    cleanup_cluster
    exit 1
fi

kubectl apply -f test-pod.yaml
wait_for_resource "kubectl get pods -n default | grep default | grep -v Pending"

if [[ -n $(kubectl logs -n marblerun -l app.kubernetes.io/name=marble-injector | tail -n 2 | grep -v "successful" | grep "omitting sgx injection") ]];
then
    echo "called the wrong webhook"
    cleanup_cluster
    exit 1
fi

if [[ -n $(kubectl describe pod test-pod | grep FailedScheduling | grep -v "Insufficient $resource_key") ]];
then
    echo "pod stuck in pending due to unrelated issue"
    cleanup_cluster
    exit 1
fi

echo -n "Checking pod tolerations: "
if [[ -n $(kubectl get pod test-pod -o jsonpath='{.spec.tolerations}' | grep -v "$resource_key") ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking pod resource limits: "
if [[ -n $(kubectl get pod test-pod -o jsonpath='{.spec.containers[0].resources.limits}' | grep -v "$resource_key") ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking env variable EDG_COORDINATOR_ADDR: "
if [[ -n $(kubectl get pod test-pod -o jsonpath='{.spec.containers[0].env[0]}' | grep -v coordinator-mesh-api.marblerun:2001) ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking env variable EDG_MARBLE_TYPE: "
if [[ -n $(kubectl get pod test-pod -o jsonpath='{.spec.containers[0].env[1]}' | grep -v test) ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking env variable EDG_MARBLE_DNS_NAMES: "
if [[ -n $(kubectl get pod test-pod -o jsonpath='{.spec.containers[0].env[2]}' | grep -v test,test.default,test.default.svc.cluster.local) ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo -n "Checking env variable EDG_MARBLE_UUID_FILE: "
if [[ -n $(kubectl get pod test-pod -o jsonpath='{.spec.containers[0].env[3]}' | grep -v "/test-uid/uuid-file") ]];
then
    echo "[FAIL]"
    cleanup_cluster
    exit 1
fi
echo "[OK]"

echo ""
kubectl delete pod test-pod

kubectl delete deployments hello-marble
kubectl delete svc hello-marble
cleanup_cluster
kubectl delete namespace marblerun
wait_for_resource "kubectl get namespaces | grep marblerun"

echo -e "\nIntegration test successful"
exit
