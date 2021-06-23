resource "aws_autoscaling_group" "workers_mapped" {
  for_each    = var.worker_groups_map
  name_prefix = "${aws_eks_cluster.this.name}-${lookup(each.value, "name", each.key)}-"
  desired_capacity = lookup(
    each.value,
    "asg_desired_capacity",
    local.workers_group_defaults["asg_desired_capacity"],
  )
  max_size = lookup(
    each.value,
    "asg_max_size",
    local.workers_group_defaults["asg_max_size"],
  )
  min_size = lookup(
    each.value,
    "asg_min_size",
    local.workers_group_defaults["asg_min_size"],
  )
  force_delete = lookup(
    each.value,
    "asg_force_delete",
    local.workers_group_defaults["asg_force_delete"],
  )
  target_group_arns = lookup(
    each.value,
    "target_group_arns",
    local.workers_group_defaults["target_group_arns"]
  )
  service_linked_role_arn = lookup(
    each.value,
    "service_linked_role_arn",
    local.workers_group_defaults["service_linked_role_arn"],
  )
  launch_configuration = aws_launch_configuration.workers_mapped[each.key].id
  vpc_zone_identifier = lookup(
    each.value,
    "subnets",
    local.workers_group_defaults["subnets"]
  )
  protect_from_scale_in = lookup(
    each.value,
    "protect_from_scale_in",
    local.workers_group_defaults["protect_from_scale_in"],
  )
  suspended_processes = lookup(
    each.value,
    "suspended_processes",
    local.workers_group_defaults["suspended_processes"]
  )
  enabled_metrics = lookup(
    each.value,
    "enabled_metrics",
    local.workers_group_defaults["enabled_metrics"]
  )
  placement_group = lookup(
    each.value,
    "placement_group",
    local.workers_group_defaults["placement_group"],
  )
  termination_policies = lookup(
    each.value,
    "termination_policies",
    local.workers_group_defaults["termination_policies"]
  )

  tags = concat(
    [
      {
        "key"                 = "Name"
        "value"               = "${aws_eks_cluster.this.name}-${lookup(each.value, "name", each.key)}-eks_asg"
        "propagate_at_launch" = true
      },
      {
        "key"                 = "kubernetes.io/cluster/${aws_eks_cluster.this.name}"
        "value"               = "owned"
        "propagate_at_launch" = true
      },
      {
        "key"                 = "k8s.io/cluster/${aws_eks_cluster.this.name}"
        "value"               = "owned"
        "propagate_at_launch" = true
      },
      {
        "key" = "k8s.io/cluster-autoscaler/${lookup(
          each.value,
          "autoscaling_enabled",
          local.workers_group_defaults["autoscaling_enabled"],
        ) ? "enabled" : "disabled"}"
        "value"               = "true"
        "propagate_at_launch" = false
      },
      {
        "key"                 = "k8s.io/cluster-autoscaler/${aws_eks_cluster.this.name}"
        "value"               = aws_eks_cluster.this.name
        "propagate_at_launch" = false
      },
      {
        "key" = "k8s.io/cluster-autoscaler/node-template/resources/ephemeral-storage"
        "value" = "${lookup(
          each.value,
          "root_volume_size",
          local.workers_group_defaults["root_volume_size"],
        )}Gi"
        "propagate_at_launch" = false
      },
    ],
    local.asg_tags,
    lookup(
      each.value,
      "tags",
      local.workers_group_defaults["tags"]
    )
  )

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity]
  }
}


resource "aws_launch_configuration" "workers_mapped" {
  for_each    = var.worker_groups_map
  name_prefix = "${aws_eks_cluster.this.name}-${var.worker_groups_map[each.key].name}-"
  associate_public_ip_address = lookup(
    each.value,
    "public_ip",
    local.workers_group_defaults["public_ip"],
  )
  security_groups = flatten([
    local.worker_security_group_id,
    var.worker_additional_security_group_ids,
    lookup(
      each.value,
      "additional_security_group_ids",
      local.workers_group_defaults["additional_security_group_ids"]
    )
  ])
  iam_instance_profile = compact([
    lookup(each.value, "iam_instance_profile_name", local.workers_group_defaults["iam_instance_profile_name"]),
    aws_iam_instance_profile.workers_mapped[each.key].name,
  ])[0]
  # the ami_id passed in from the calling stack is (in our case) emtpy, sop we have to strip that empty string out with compact()
  image_id = compact(
    [lookup(each.value, "ami_id", ""),
    local.workers_group_defaults["ami_id"]]
  )[0]
  instance_type = lookup(
    each.value,
    "instance_type",
    local.workers_group_defaults["instance_type"],
  )
  key_name = lookup(
    each.value,
    "key_name",
    local.workers_group_defaults["key_name"],
  )

  user_data_base64 = base64encode(templatefile("${path.module}/templates/userdata.sh.tpl",
    {
      cluster_name        = aws_eks_cluster.this.name
      endpoint            = aws_eks_cluster.this.endpoint
      cluster_auth_base64 = aws_eks_cluster.this.certificate_authority[0].data
      pre_userdata = lookup(
        each.value,
        "pre_userdata",
        local.workers_group_defaults["pre_userdata"],
      )
      additional_userdata = lookup(
        each.value,
        "additional_userdata",
        local.workers_group_defaults["additional_userdata"],
      )
      bootstrap_extra_args = lookup(
        each.value,
        "bootstrap_extra_args",
        local.workers_group_defaults["bootstrap_extra_args"],
      )
      kubelet_extra_args = lookup(
        each.value,
        "kubelet_extra_args",
        local.workers_group_defaults["kubelet_extra_args"],
      )
    }
    )
  )
  ebs_optimized = lookup(
    each.value,
    "ebs_optimized",
    lookup(
      local.ebs_optimized,
      lookup(
        each.value,
        "instance_type",
        local.workers_group_defaults["instance_type"],
      ),
      false,
    ),
  )
  enable_monitoring = lookup(
    each.value,
    "enable_monitoring",
    local.workers_group_defaults["enable_monitoring"],
  )
  spot_price = lookup(
    each.value,
    "spot_price",
    local.workers_group_defaults["spot_price"],
  )
  placement_tenancy = lookup(
    each.value,
    "placement_tenancy",
    local.workers_group_defaults["placement_tenancy"],
  )

  root_block_device {
    volume_size = lookup(
      each.value,
      "root_volume_size",
      local.workers_group_defaults["root_volume_size"],
    )
    volume_type = lookup(
      each.value,
      "root_volume_type",
      local.workers_group_defaults["root_volume_type"],
    )
    iops = lookup(
      each.value,
      "root_iops",
      local.workers_group_defaults["root_iops"],
    )
    encrypted = lookup(
      each.value,
      "root_encrypted",
      local.workers_group_defaults["root_encrypted"],
    )
    delete_on_termination = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "workers_mapped" {
  count       = var.worker_create_security_group ? 1 : 0
  name_prefix = aws_eks_cluster.this.name
  description = "Security group for all nodes in the cluster."
  vpc_id      = var.vpc_id
  tags = merge(
    var.tags,
    {
      "Name"                                               = "${aws_eks_cluster.this.name}-eks_worker_sg"
      "kubernetes.io/cluster/${aws_eks_cluster.this.name}" = "owned"
    },
  )
}

resource "aws_security_group_rule" "workers_egress_internet_mapped" {
  count             = var.worker_create_security_group ? 1 : 0
  description       = "Allow nodes all egress to the Internet."
  protocol          = "-1"
  security_group_id = aws_security_group.workers_mapped[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  to_port           = 0
  type              = "egress"
}

resource "aws_security_group_rule" "workers_ingress_self_mapped" {
  count                    = var.worker_create_security_group ? 1 : 0
  description              = "Allow node to communicate with each other."
  protocol                 = "-1"
  security_group_id        = aws_security_group.workers_mapped[0].id
  source_security_group_id = aws_security_group.workers_mapped[0].id
  from_port                = 0
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "workers_ingress_cluster_mapped" {
  count                    = var.worker_create_security_group ? 1 : 0
  description              = "Allow workers pods to receive communication from the cluster control plane."
  protocol                 = "tcp"
  security_group_id        = aws_security_group.workers_mapped[0].id
  source_security_group_id = local.cluster_security_group_id
  from_port                = var.worker_sg_ingress_from_port
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "workers_ingress_cluster_kubelet_mapped" {
  count                    = var.worker_create_security_group ? var.worker_sg_ingress_from_port > 10250 ? 1 : 0 : 0
  description              = "Allow workers Kubelets to receive communication from the cluster control plane."
  protocol                 = "tcp"
  security_group_id        = aws_security_group.workers_mapped[0].id
  source_security_group_id = local.cluster_security_group_id
  from_port                = 10250
  to_port                  = 10250
  type                     = "ingress"
}

resource "aws_security_group_rule" "workers_ingress_cluster_https_mapped" {
  count                    = var.worker_create_security_group ? 1 : 0
  description              = "Allow pods running extension API servers on port 443 to receive communication from cluster control plane."
  protocol                 = "tcp"
  security_group_id        = aws_security_group.workers_mapped[0].id
  source_security_group_id = local.cluster_security_group_id
  from_port                = 443
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_iam_role" "workers_mapped" {
  count                 = var.manage_worker_iam_resources ? 1 : 0
  name_prefix           = aws_eks_cluster.this.name
  assume_role_policy    = data.aws_iam_policy_document.workers_assume_role_policy.json
  permissions_boundary  = var.permissions_boundary
  path                  = var.iam_path
  force_detach_policies = true
  tags                  = var.tags
}


resource "aws_iam_instance_profile" "workers_mapped" {
  for_each    = var.manage_worker_iam_resources ? toset(keys(var.worker_groups_map)) : toset([])
  name_prefix = aws_eks_cluster.this.name
  role = lookup(
    var.worker_groups_map[each.value],
    "iam_role_id",
    local.default_iam_role_id,
  )

  path = var.iam_path
}


resource "aws_iam_role_policy_attachment" "workers_AmazonEKSWorkerNodePolicy_mapped" {
  count      = var.manage_worker_iam_resources ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.workers_mapped[0].name
}

resource "aws_iam_role_policy_attachment" "workers_AmazonEKS_CNI_Policy_mapped" {
  count      = var.manage_worker_iam_resources ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.workers_mapped[0].name
}

resource "aws_iam_role_policy_attachment" "workers_AmazonEC2ContainerRegistryReadOnly_mapped" {
  count      = var.manage_worker_iam_resources ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.workers_mapped[0].name
}

# --- add SSM policies to the worker IAM role --------------------------
# allow management by SSM
resource "aws_iam_role_policy_attachment" "worker_role_attach_AmazonSSMManagedInstanceCore" {
  count      = var.manage_worker_iam_resources ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.workers_mapped[0].name
}

resource "aws_iam_role_policy_attachment" "worker_ssm_logs" {
  role       = aws_iam_role.workers_mapped[0].name
  policy_arn = aws_iam_policy.worker_ssm_logs.arn
}
resource "aws_iam_policy" "worker_ssm_logs" {
  name_prefix = "eks-worker-logging-${aws_eks_cluster.this.name}-cluster"
  description = "EKS worker nodes SSM Agent logging ${aws_eks_cluster.this.name}"
  policy      = data.aws_iam_policy_document.worker_ssm_logs.json
}

data "aws_iam_policy_document" "worker_ssm_logs" {
  statement {
    sid    = "ssmAgentLogging"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
      "logs:GetLogEvents"
    ]

    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/ssm/agents:*",
    "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/ssm/sessions:*"]
  }
  statement {
    sid    = "ssmAgentLoggroups"
    effect = "Allow"

    actions = [
      "logs:DescribeLogGroups"
    ]

    resources = [
      "arn:aws:logs:*:*:*"
    ]
  }
}

resource "aws_iam_role_policy_attachment" "workers_additional_policies_mapped" {
  count      = var.manage_worker_iam_resources ? length(var.workers_additional_policies) : 0
  role       = aws_iam_role.workers_mapped[0].name
  policy_arn = var.workers_additional_policies[count.index]
}

resource "null_resource" "tags_as_list_of_maps_mapped" {
  count = length(keys(var.tags))

  triggers = {
    key                 = keys(var.tags)[count.index]
    value               = values(var.tags)[count.index]
    propagate_at_launch = "true"
  }
}

resource "aws_iam_role_policy_attachment" "workers_autoscaling_mapped" {
  count      = var.manage_worker_iam_resources ? 1 : 0
  policy_arn = aws_iam_policy.worker_autoscaling[0].arn
  role       = aws_iam_role.workers_mapped[0].name
}

resource "aws_iam_policy" "worker_autoscaling_mapped" {
  count       = var.manage_worker_iam_resources ? 1 : 0
  name_prefix = "eks-worker-autoscaling-${aws_eks_cluster.this.name}"
  description = "EKS worker node autoscaling policy for cluster ${aws_eks_cluster.this.name}"
  policy      = data.aws_iam_policy_document.worker_autoscaling.json
  path        = var.iam_path
}

data "aws_iam_policy_document" "worker_autoscaling_mapped" {
  statement {
    sid    = "eksWorkerAutoscalingAll"
    effect = "Allow"

    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeTags",
      "ec2:DescribeLaunchTemplateVersions",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "eksWorkerAutoscalingOwn"
    effect = "Allow"

    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "autoscaling:UpdateAutoScalingGroup",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/kubernetes.io/cluster/${local.aws_eks_cluster_name}"
      values   = ["owned"]
    }

    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/k8s.io/cluster-autoscaler/enabled"
      values   = ["true"]
    }
  }
}
