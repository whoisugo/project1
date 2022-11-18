provider "aws" {
  region = "us-east-1"
}

locals {
  s3_origin_id = "adv-devint-ue-kms-gemini-s3"
}

resource "aws_kms_key" "adv-devint-ue-kms-gemini-s3" {
  deletion_window_in_days  = var.deletion_window_in_days
  enable_key_rotation      = var.enable_key_rotation
  description              = var.description
  key_usage                = var.key_usage
  customer_master_key_spec = var.customer_master_key_spec
  multi_region             = var.multi_region
}

resource "aws_kms_alias" "adv-devint-ue-kms-gemini-s3" {
  name          = var.alias
  target_key_id = join("", aws_kms_key.adv-devint-ue-kms-gemini-s3.*.id)
}

resource "aws_s3_bucket" "adv-devint-ue-kms-gemini-web" {
  bucket              = "adv-devint-ue-kms-gemini-web"
  object_lock_enabled = false
}


resource "aws_s3_bucket" "adv-devint-ue-kms-general-bucket" {
  bucket              = "adv-devint-ue-kms-general-bucket"
  object_lock_enabled = false
}

resource "aws_s3_bucket_acl" "a_acl" {
  bucket = aws_s3_bucket.adv-devint-ue-kms-gemini-web.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "b_acl" {
  bucket = aws_s3_bucket.adv-devint-ue-kms-general-bucket.id
  acl    = "private"
}


resource "aws_s3_bucket_server_side_encryption_configuration" "adv-devint-ue-kms-gemini-web-encryption" {
  bucket = aws_s3_bucket.adv-devint-ue-kms-gemini-web.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "adv-devint-ue-kms-gemini-general-encryption" {
  bucket = aws_s3_bucket.adv-devint-ue-kms-general-bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.adv-devint-ue-kms-gemini-s3.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "adv-devint-ue-kms-gemini-web-ver" {
  bucket = aws_s3_bucket.adv-devint-ue-kms-gemini-web.id
  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_versioning" "adv-devint-ue-kms-general-bucket-ver" {
  bucket = aws_s3_bucket.adv-devint-ue-kms-general-bucket.id
  versioning_configuration {
    status = "Disabled"
  }
}


resource "aws_cloudfront_origin_access_identity" "adv-devint-cloudfront-origin-access-identity" {
  comment = "Some comment"
}

resource "aws_cloudfront_distribution" "adv-devint-ue1-cloudfront-gemini" {
    origin {
    domain_name = aws_s3_bucket.adv-devint-ue-kms-gemini-web.bucket_regional_domain_name

    origin_id   = local.s3_origin_id
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.adv-devint-cloudfront-origin-access-identity.cloudfront_access_identity_path
    }
  }
  web_acl_id = aws_waf_web_acl.waf_acl.id
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "https-only"

  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "DE"]
    }
  }
  


  viewer_certificate {
    cloudfront_default_certificate = true
  }
  }


  #################################################################################################################
  # WAF
  #################################################################################################################

# Creating the IP Set tp be defined in AWS WAF 
 
resource "aws_waf_ipset" "ipset" {
   name = "adv-devint-ipset"
   ip_set_descriptors {
     type = "IPV4"
     value = "10.111.0.0/20"
   }
}
 
# Creating the AWS WAF rule that will be applied on AWS Web ACL
 
resource "aws_waf_rule" "waf_rule" { 
  depends_on = [aws_waf_ipset.ipset]
  name        = "adv-devint-waf-rule"
  metric_name = "advdevintue1wafgeminiweb"
  predicates {
    data_id = aws_waf_ipset.ipset.id
    negated = false
    type    = "IPMatch"
  }
}
 
# Creating the Rule Group which will be applied on  AWS Web ACL
 
resource "aws_waf_rule_group" "rule_group" {  
  name        = "adv-devint-rule-group"
  metric_name = "advdevintue1wafgeminiweb"
 
  activated_rule {
    action {
      type = "COUNT"
    }
    priority = 50
    rule_id  = aws_waf_rule.waf_rule.id
  }
}
 
# Creating the Web ACL component in AWS WAF
 
resource "aws_waf_web_acl" "waf_acl" {
  depends_on = [ 
     aws_waf_rule.waf_rule,
     aws_waf_ipset.ipset,
      ]
  name        = "adv-devint-ue1-waf-gemini-web"
  metric_name = "advdevintue1wafgeminiweb"
  default_action {
    type = "ALLOW"
  }
  rules {
    action {
      type = "BLOCK"
    }
    priority = 1
    rule_id  = aws_waf_rule.waf_rule.id
    type     = "REGULAR"
 }
}