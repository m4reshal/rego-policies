#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

command -v oc &> /dev/null || { echo >&2 'ERROR: oc not installed - Aborting'; exit 1; }
command -v konstraint &> /dev/null || { echo >&2 'ERROR: konstraint not installed - Aborting'; exit 1; }

gatekeeper_version="v3.10.0"

cleanup_gatekeeper_constraints() {
  echo ""
  echo "Deleting all ConstraintTemplates..."
  oc delete constrainttemplate.templates.gatekeeper.sh --all --ignore-not-found=true || true

  find policy/* \( -name "template.yaml" -o -name "constraint.yaml" \) -type f -exec rm -f {} \;
}

cleanup_gatekeeper() {
  echo ""
  echo "Cleaning up previous gatekeeper installation..."
  oc delete config.config.gatekeeper.sh -n gatekeeper-system --all --ignore-not-found=true || true
  oc delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${gatekeeper_version}/deploy/gatekeeper.yaml --ignore-not-found=true
  oc delete -f gatekeeper/gatekeeper-template-manager.yml --ignore-not-found=true

  oc delete clusterrole/gatekeeper-allow-anyuid-scc --ignore-not-found=true
  oc delete rolebinding/gatekeeper-anyuid-scc --ignore-not-found=true
}

deploy_gatekeeper() {
  echo ""
  echo "Patching control-plane related namespaces so that OPA ignores them..."

  excludedNamespaces=()
  for namespace in $(oc get namespaces -o jsonpath='{.items[*].metadata.name}' | xargs); do
    if [[ "${namespace}" =~ openshift.* ]] || [[ "${namespace}" =~ kube.* ]] || [[ "${namespace}" =~ default ]]; then
      oc patch namespace/${namespace} -p='{"metadata":{"labels":{"admission.gatekeeper.sh/ignore":"true"}}}'
      excludedNamespaces+=("\"--exempt-namespace=${namespace}\"")
    else
      # Probably a users project, so leave it alone
      echo "Skipping: ${namespace}"
    fi
  done

  local excludedNamespacesComma
  excludedNamespacesComma=$(echo "${excludedNamespaces[@]}" | tr ' ' ',')

  echo ""
  echo "Deploying gatekeeper ${gatekeeper_version}..."
  oc create -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${gatekeeper_version}/deploy/gatekeeper.yaml

  echo ""
  echo "Patching gatekeeper to work on OCP..."
  oc create clusterrole gatekeeper-allow-anyuid-scc --verb=use --resource=securitycontextconstraints.security.openshift.io --resource-name=anyuid
  oc create rolebinding gatekeeper-anyuid-scc --serviceaccount=gatekeeper-system:gatekeeper-admin --clusterrole=gatekeeper-allow-anyuid-scc -n gatekeeper-system

  oc patch deployment/gatekeeper-audit --type json -p='[{"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/runAsUser"}]' -n gatekeeper-system
  oc patch deployment/gatekeeper-controller-manager --type json -p='[{"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/runAsUser"}]' -n gatekeeper-system

  echo ""
  echo "Patching gatekeeper to enable emit-admission-events..."

  oc patch Deployment/gatekeeper-audit --type json -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--emit-admission-events=true" }]' -n gatekeeper-system
  oc patch Deployment/gatekeeper-controller-manager --type json -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--emit-admission-events=true" }]' -n gatekeeper-system

  echo ""
  echo "Patching gatekeeper to include core namespaces in exempt-namespace..."
  #HACK: to make sure the above patch is finished
  sleep 1s
  oc get deployment/gatekeeper-controller-manager -n gatekeeper-system -o json | jq ".spec.template.spec.containers[0].args |= . + [${excludedNamespacesComma}]" | oc apply -f -

  echo ""
  echo "Waiting for gatekeeper to be ready..."
  oc rollout status Deployment/gatekeeper-audit -n gatekeeper-system --watch=true
  oc rollout status Deployment/gatekeeper-controller-manager -n gatekeeper-system --watch=true

  oc create -f gatekeeper/config.yml -n gatekeeper-system
  oc create -f gatekeeper/gatekeeper-template-manager.yml
}

patch_namespaceselector_for_webhook() {
  echo ""
  echo "Patching ValidatingWebhookConfiguration/gatekeeper-validating-webhook-configuration to only watch namespaces with: 'redhat-cop.github.com/gatekeeper-active == true'..."
  oc patch ValidatingWebhookConfiguration/gatekeeper-validating-webhook-configuration -p='{"webhooks":[{"name":"validation.gatekeeper.sh","namespaceSelector":{"matchExpressions":[{"key":"redhat-cop.github.com/gatekeeper-active","operator":"In","values":["true"]}]}}]}'

  echo ""
  echo "Restarting Gatekeeper and waiting for it to be ready..."
  oc delete pods --all -n gatekeeper-system
  oc rollout status Deployment/gatekeeper-audit -n gatekeeper-system --watch=true
  oc rollout status Deployment/gatekeeper-controller-manager -n gatekeeper-system --watch=true
}

restart_gatekeeper() {
  echo ""
  echo "Restarting Gatekeeper and waiting for it to be ready..."
  oc delete pods --all -n gatekeeper-system
  oc rollout status Deployment/gatekeeper-audit -n gatekeeper-system --watch=true
  oc rollout status Deployment/gatekeeper-controller-manager -n gatekeeper-system --watch=true
}

generate_constraints() {
  echo "Creating ConstraintTemplates via konstraint..."
  konstraint doc -o POLICIES.md
  konstraint create --constraint-template-version v1

  # shellcheck disable=SC2038
  for file in $(find policy/* \( -name "template.yaml" \) -type f | xargs); do
    if [[ "${file}" == *"/combine/"* ]]; then
      # the data is 'off-cluster' so cant be tested against gatekeeper
      rm -f "${file}"
    elif [[ "${file}" == *"/ocp/deprecated/"* ]]; then
      # tests cant be deployed to a 4.x cluster so cant be tested against gatekeeper
      rm -f "${file}"
    elif [[ "${file}" == *"/ocp/bestpractices/deploymentconfig-triggers-notset/"* ]]; then
      # OCP API-Server adds a default ConfigChange trigger by default so cant be tested against gatekeeper
      rm -f "${file}"
    elif [[ "${file}" == *"/ocp/bestpractices/rolebinding-roleref-apigroup-notset/"* ]]; then
      # OCP API-Server does not accept data matching this criteria but they are good for conftest when people are moving from 3.11 to 4.x
      rm -f "${file}"
    elif [[ "${file}" == *"/ocp/bestpractices/rolebinding-roleref-kind-notset/"* ]]; then
      # OCP API-Server does not accept data matching this criteria but they are good for conftest when people are moving from 3.11 to 4.x
      rm -f "${file}"
    elif [[ "${file}" == *"/podman/"* ]]; then
      # the data is 'off-cluster' so cant be tested against gatekeeper
      rm -f "${file}"
    fi
  done
}

deploy_constraints() {
  echo ""
  echo "Deploying Constraints..."

  for file in $(find policy/* -name "template.yaml"  -type f -exec dirname {} \; | sort | xargs); do
    echo ""
    echo "Policy: ${file}"

    files=("template.yaml" "constraint.yaml")
    for yamlname in "${files[@]}"; do
      name=$(oc create -f "${file}/${yamlname}" -n gatekeeper-system -o name || exit $?)
      echo "${name}"

      until oc get ${name} -o json | jq ".status.byPod | length" | grep -q "4";
      do
        echo "-> Waiting for: .status.byPod | length == 4"
        sleep 5s
      done

      until [[ -z $(oc get ${name} -o json | jq "select(.status.byPod[].errors != null)") ]];
      do
        echo "-> Waiting for: .status.byPod[].errors == ''"
        sleep 5s
      done
    done
  done
}

# Process arguments
case $1 in
  deploy_gatekeeper)
    cleanup_gatekeeper_constraints
    cleanup_gatekeeper
    deploy_gatekeeper
    ;;
  patch_namespaceselector)
    patch_namespaceselector_for_webhook
    ;;
  deploy_constraints)
    cleanup_gatekeeper_constraints
    restart_gatekeeper
    generate_constraints
    deploy_constraints
    ;;
  cleanup_gatekeeper)
    cleanup_gatekeeper_constraints
    cleanup_gatekeeper
    ;;
  *)
    echo "Not an option"
    exit 1
esac
