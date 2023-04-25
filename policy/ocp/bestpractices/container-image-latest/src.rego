# @title RHCOP-OCP_BESTPRACT-00003: Container image is not set as latest
#
# Images should use immutable tags. Today's latest is not tomorrows latest.
#
# @kinds apps.openshift.io/DeploymentConfig apps/DaemonSet apps/Deployment apps/Job apps/ReplicaSet core/ReplicationController apps/StatefulSet core/Pod batch/CronJob
package ocp.bestpractices.container_image_latest

import data.lib.konstraint.core as konstraint_core
import data.lib.openshift

violation[msg] {
  openshift.is_policy_active("RHCOP-OCP_BESTPRACT-00003")
  container := openshift.containers[_]

  has_latest_tag(container)

  msg := konstraint_core.format_with_id(sprintf("%s/%s: container '%s' is using the latest tag for its image (%s), which is an anti-pattern.", [konstraint_core.kind, konstraint_core.name, container.name, container.image]), "RHCOP-OCP_BESTPRACT-00003")
}
has_latest_tag(c) {
  endswith(c.image, ":latest")
}
has_latest_tag(c) {
  contains(c.image, ":") == false
}
