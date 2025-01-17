#!/usr/bin/env bats

load bats-support-clone
load bats-support-setup
load test_helper/bats-support/load
load test_helper/redhatcop-bats-library/load

setup_file() {
  oc api-versions --request-timeout=5s || return $?
  oc cluster-info || return $?

  export project_name="regopolicies-undertest-$(date +'%d%m%Y-%H%M%S')"
  export project_name_disabled="regopolicies-undertest-disabled-$(date +'%d%m%Y-%H%M%S')"

  _setup_file "${project_name}" "${project_name_disabled}"
}

teardown_file() {
  _teardown_file "${project_name}" "${project_name_disabled}"
}

teardown() {
  _teardown "${tmp}"
}

####################
# all-namespaces
####################

@test "policy/ocp/bestpractices/_all-namespaces" {
  alltmp=$(split_files "policy/ocp/bestpractices/_all-namespaces/test_data/integration")

  cmd="oc create -f ${alltmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${alltmp}"
  [ "$status" -eq 0 ]
}

####################
# ocp/bestpractices
####################

@test "policy/ocp/bestpractices/common-k8s-labels-notset" {
  tmp=$(split_files "policy/ocp/bestpractices/common-k8s-labels-notset/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [commonk8slabelsnotset] RHCOP-OCP_BESTPRACT-00001: Deployment/nolabels"* ]]
  [[ "${lines[1]}" == *"denied the request: [commonk8slabelsnotset] RHCOP-OCP_BESTPRACT-00001: DeploymentConfig/nolabels"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-env-maxmemory-notset" {
  tmp=$(split_files "policy/ocp/bestpractices/container-env-maxmemory-notset/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}
  
  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerenvmaxmemorynotset] RHCOP-OCP_BESTPRACT-00002: Deployment/nodownwardmemoryenv"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerenvmaxmemorynotset] RHCOP-OCP_BESTPRACT-00002: DeploymentConfig/nodownwardmemoryenv"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-image-latest" {
  tmp=$(split_files "policy/ocp/bestpractices/container-image-latest/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerimagelatest] RHCOP-OCP_BESTPRACT-00003: Deployment/imageuseslatesttag"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerimagelatest] RHCOP-OCP_BESTPRACT-00003: DeploymentConfig/imageuseslatesttag"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-image-unknownregistries" {
  tmp=$(split_files "policy/ocp/bestpractices/container-image-unknownregistries/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerimageunknownregistries] RHCOP-OCP_BESTPRACT-00004: Deployment/imagefromunknownregistry"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerimageunknownregistries] RHCOP-OCP_BESTPRACT-00004: DeploymentConfig/imagefromunknownregistry"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-java-xmx-set" {
  tmp=$(split_files "policy/ocp/bestpractices/container-java-xmx-set/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerjavaxmxset] RHCOP-OCP_BESTPRACT-00005: Deployment/xmxviacommand"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerjavaxmxset] RHCOP-OCP_BESTPRACT-00005: Deployment/xmxviaargs"* ]]
  [[ "${lines[2]}" == *"denied the request: [containerjavaxmxset] RHCOP-OCP_BESTPRACT-00005: Deployment/xmxviaenv"* ]]
  [[ "${lines[3]}" == *"denied the request: [containerjavaxmxset] RHCOP-OCP_BESTPRACT-00005: DeploymentConfig/xmxviacommand"* ]]
  [[ "${lines[4]}" == *"denied the request: [containerjavaxmxset] RHCOP-OCP_BESTPRACT-00005: DeploymentConfig/xmxviaargs"* ]]
  [[ "${lines[5]}" == *"denied the request: [containerjavaxmxset] RHCOP-OCP_BESTPRACT-00005: DeploymentConfig/xmxviaenv"* ]]
  [[ "${#lines[@]}" -eq 6 ]]
}

@test "policy/ocp/bestpractices/container-labelkey-inconsistent" {
  tmp=$(split_files "policy/ocp/bestpractices/container-labelkey-inconsistent/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerlabelkeyinconsistent] RHCOP-OCP_BESTPRACT-00006: Deployment/nonestandardlabel"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerlabelkeyinconsistent] RHCOP-OCP_BESTPRACT-00006: DeploymentConfig/nonestandardlabel"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-liveness-readinessprobe-equal" {
  tmp=$(split_files "policy/ocp/bestpractices/container-liveness-readinessprobe-equal/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerlivenessreadinessprobeequal] RHCOP-OCP_BESTPRACT-00007: Deployment/probssetaresame"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerlivenessreadinessprobeequal] RHCOP-OCP_BESTPRACT-00007: DeploymentConfig/probssetaresame"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-livenessprobe-notset" {
  tmp=$(split_files "policy/ocp/bestpractices/container-livenessprobe-notset/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerlivenessprobenotset] RHCOP-OCP_BESTPRACT-00008: Deployment/noproblivenessset"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerlivenessprobenotset] RHCOP-OCP_BESTPRACT-00008: DeploymentConfig/noproblivenessset"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-readinessprobe-notset" {
  tmp=$(split_files "policy/ocp/bestpractices/container-readinessprobe-notset/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerreadinessprobenotset] RHCOP-OCP_BESTPRACT-00009: Deployment/noreadinessprob"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerreadinessprobenotset] RHCOP-OCP_BESTPRACT-00009: DeploymentConfig/noreadinessprob"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-resources-limits-cpu-set" {
  tmp=$(split_files "policy/ocp/bestpractices/container-resources-limits-cpu-set/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerresourceslimitscpuset] RHCOP-OCP_BESTPRACT-00010: Deployment/resourceslimitscpuset"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerresourceslimitscpuset] RHCOP-OCP_BESTPRACT-00010: DeploymentConfig/resourceslimitscpuset"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-resources-limits-memory-greater-than" {
  tmp=$(split_files "policy/ocp/bestpractices/container-resources-limits-memory-greater-than/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerresourceslimitsmemorygreaterthan] RHCOP-OCP_BESTPRACT-00011: Deployment/memorylimittoolarge"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerresourceslimitsmemorygreaterthan] RHCOP-OCP_BESTPRACT-00011: DeploymentConfig/memorylimittoolarge"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-resources-limits-memory-notset" {
  tmp=$(split_files "policy/ocp/bestpractices/container-resources-limits-memory-notset/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerresourceslimitsmemorynotset] RHCOP-OCP_BESTPRACT-00012: Deployment/resourcelimitsmemorynotset"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerresourceslimitsmemorynotset] RHCOP-OCP_BESTPRACT-00012: DeploymentConfig/resourcelimitsmemorynotset"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-resources-memoryunit-incorrect" {
  tmp=$(split_files "policy/ocp/bestpractices/container-resources-memoryunit-incorrect/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[2]}" == *"denied the request: [containerresourcesmemoryunitincorrect] RHCOP-OCP_BESTPRACT-00013: Deployment/invalidresourcesrequestsmemoryunits"* ]]
  [[ "${lines[3]}" == *"denied the request: [containerresourcesmemoryunitincorrect] RHCOP-OCP_BESTPRACT-00013: Deployment/invalidresourceslimitsmemoryunits"* ]]
  [[ "${lines[4]}" == *"denied the request: [containerresourcesmemoryunitincorrect] RHCOP-OCP_BESTPRACT-00013: DeploymentConfig/invalidresourcesrequestsmemoryunits"* ]]
  [[ "${lines[5]}" == *"denied the request: [containerresourcesmemoryunitincorrect] RHCOP-OCP_BESTPRACT-00013: DeploymentConfig/invalidresourceslimitsmemoryunits"* ]]
  [[ "${#lines[@]}" -eq 6 ]]
}

@test "policy/ocp/bestpractices/container-resources-requests-cpuunit-incorrect" {
  tmp=$(split_files "policy/ocp/bestpractices/container-resources-requests-cpuunit-incorrect/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerresourcesrequestscpuunitincorrect] RHCOP-OCP_BESTPRACT-00014: Deployment/invalidresourcesrequestcpuunits"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerresourcesrequestscpuunitincorrect] RHCOP-OCP_BESTPRACT-00014: DeploymentConfig/invalidresourcesrequestcpuunits"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-resources-requests-memory-greater-than" {
  tmp=$(split_files "policy/ocp/bestpractices/container-resources-requests-memory-greater-than/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containerresourcesrequestsmemorygreaterthan] RHCOP-OCP_BESTPRACT-00015: Deployment/memoryrequesttoolarge"* ]]
  [[ "${lines[1]}" == *"denied the request: [containerresourcesrequestsmemorygreaterthan] RHCOP-OCP_BESTPRACT-00015: DeploymentConfig/memoryrequesttoolarge"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-secret-mounted-envs" {
  tmp=$(split_files "policy/ocp/bestpractices/container-secret-mounted-envs/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containersecretmountedenvs] RHCOP-OCP_BESTPRACT-00016: Deployment/secretenvvars"* ]]
  [[ "${lines[1]}" == *"denied the request: [containersecretmountedenvs] RHCOP-OCP_BESTPRACT-00016: DeploymentConfig/secretenvvars"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-volumemount-inconsistent-path" {
  tmp=$(split_files "policy/ocp/bestpractices/container-volumemount-inconsistent-path/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containervolumemountinconsistentpath] RHCOP-OCP_BESTPRACT-00017: Deployment/notvarrunvolumemountspath"* ]]
  [[ "${lines[1]}" == *"denied the request: [containervolumemountinconsistentpath] RHCOP-OCP_BESTPRACT-00017: DeploymentConfig/notvarrunvolumemountspath"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/container-volumemount-missing" {
  tmp=$(split_files "policy/ocp/bestpractices/container-volumemount-missing/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [containervolumemountmissing] RHCOP-OCP_BESTPRACT-00018: Deployment/missingvolumemount"* ]]
  [[ "${lines[1]}" == *"denied the request: [containervolumemountmissing] RHCOP-OCP_BESTPRACT-00018: DeploymentConfig/missingvolumemount"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/deploymentconfig-triggers-containername" {
  tmp=$(split_files "policy/ocp/bestpractices/deploymentconfig-triggers-containername/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [deploymentconfigtriggerscontainername] RHCOP-OCP_BESTPRACT-00027: DeploymentConfig/deploymentconfigtriggerscontainername"* ]]
  [[ "${#lines[@]}" -eq 1 ]]
}

@test "policy/ocp/bestpractices/pod-hostnetwork" {
  tmp=$(split_files "policy/ocp/bestpractices/pod-hostnetwork/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[1]}" == *"denied the request: [podhostnetwork] RHCOP-OCP_BESTPRACT-00020: Deployment/hostnetworkisset"* ]]
  [[ "${lines[2]}" == *"denied the request: [podhostnetwork] RHCOP-OCP_BESTPRACT-00020: DeploymentConfig/hostnetworkisset"* ]]
  [[ "${#lines[@]}" -eq 3 ]]
}

@test "policy/ocp/bestpractices/pod-replicas-below-one" {
  tmp=$(split_files "policy/ocp/bestpractices/pod-replicas-below-one/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [podreplicasbelowone] RHCOP-OCP_BESTPRACT-00021: Deployment/replicaisone"* ]]
  [[ "${lines[1]}" == *"denied the request: [podreplicasbelowone] RHCOP-OCP_BESTPRACT-00021: DeploymentConfig/replicaisone"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/pod-replicas-not-odd" {
  tmp=$(split_files "policy/ocp/bestpractices/pod-replicas-not-odd/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [podreplicasnotodd] RHCOP-OCP_BESTPRACT-00022: Deployment/replicaiseven"* ]]
  [[ "${lines[1]}" == *"denied the request: [podreplicasnotodd] RHCOP-OCP_BESTPRACT-00022: DeploymentConfig/replicaiseven"* ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

@test "policy/ocp/bestpractices/route-tls-termination-notset" {
  tmp=$(split_files "policy/ocp/bestpractices/route-tls-termination-notset/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [routetlsterminationnotset] RHCOP-OCP_BESTPRACT-00025: Route/tlsterminationnotset"* ]]
  [[ "${#lines[@]}" -eq 1 ]]
}

####################
# ocp/bestpractices - with disabled policy label on project
####################

@test "policy/ocp/bestpractices/_all-namespaces - disabled policy label" {
  alltmp=$(split_files "policy/ocp/bestpractices/_all-namespaces/test_data/integration")

  cmd="oc create -f ${alltmp} -n ${project_name_disabled}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${alltmp}"
  [ "$status" -eq 0 ]
}

@test "policy/ocp/bestpractices/common-k8s-labels-notset - disabled policy label" {
  tmp=$(split_files "policy/ocp/bestpractices/common-k8s-labels-notset/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name_disabled}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 0 ]

  [[ "${lines[0]}" == "deployment.apps/nolabels created" ]]
  [[ "${lines[1]}" == "deploymentconfig.apps.openshift.io/nolabels created" ]]
  [[ "${#lines[@]}" -eq 2 ]]
}

####################
# ocp/requiresinventory
####################

@test "policy/ocp/requiresinventory/deployment-has-matching-poddisruptionbudget" {
  tmp=$(split_files "policy/ocp/requiresinventory/deployment-has-matching-poddisruptionbudget/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]

  [[ "${lines[0]}" == *"denied the request: [deploymenthasmatchingpoddisruptionbudget] RHCOP-OCP_REQ_INV-00001: Deployment/hasmissingpdb"* ]]
  [[ "${#lines[@]}" -eq 1 ]]
}

@test "policy/ocp/requiresinventory/deployment-has-matching-pvc" {
  tmp=$(split_files "policy/ocp/requiresinventory/deployment-has-matching-pvc/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [deploymenthasmatchingpvc] RHCOP-OCP_REQ_INV-00002: Deployment/hasmissingpvc"* ]]
  [[ "${#lines[@]}" -eq 1 ]]
}

@test "policy/ocp/requiresinventory/deployment-has-matching-service" {
  tmp=$(split_files "policy/ocp/requiresinventory/deployment-has-matching-service/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [deploymenthasmatchingservice] RHCOP-OCP_REQ_INV-00003: Deployment/hasmissingsvc"* ]]
  [[ "${#lines[@]}" -eq 1 ]]
}

@test "policy/ocp/requiresinventory/deployment-has-matching-serviceaccount" {
  tmp=$(split_files "policy/ocp/requiresinventory/deployment-has-matching-serviceaccount/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [deploymenthasmatchingserviceaccount] RHCOP-OCP_REQ_INV-00004: Deployment/hasmissingsvcaccount"* ]]
  [[ "${#lines[@]}" -eq 1 ]]
}

@test "policy/ocp/requiresinventory/service-has-matching-servicemonitor" {
  tmp=$(split_files "policy/ocp/requiresinventory/service-has-matching-servicemonitor/test_data/integration")

  cmd="oc create -f ${tmp} -n ${project_name}"
  run ${cmd}

  print_info "${status}" "${output}" "${cmd}" "${tmp}"
  [ "$status" -eq 1 ]
  [[ "${lines[0]}" == *"denied the request: [servicehasmatchingservicemonitor] RHCOP-OCP_REQ_INV-00005: Service/hasmissingsvcmon"* ]]
  [[ "${#lines[@]}" -eq 1 ]]
}
