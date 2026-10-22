resource "aws_s3_bucket" "local_lab" {
  bucket = "osop-local-lab-example"
}

resource "aws_s3_bucket_public_access_block" "local_lab" {
  bucket                  = aws_s3_bucket.local_lab.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
