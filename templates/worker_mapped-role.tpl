    - rolearn: ${arn_skeleton}/${worker_role_name}
      username: system:node:{{EC2PrivateDNSName}}
      groups:
        - system:bootstrappers
        - system:nodes
