resource "local_file" "kubeconfig" {
  count    = var.write_kubeconfig ? 1 : 0
  content  = local.kubeconfig
  filename = "${var.config_output_path}kubeconfig_${var.cluster_name}"
}

