#!/bin/bash

export OIDC_S3_BUCKET_NAME=totopenny-oidc
export S3_BUCKET_NAME=totopenny

export DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
export PKCS_KEY="sa-signer-pkcs8.pub"
export POD_IDENTITY_WEBHOOK_NAMESPACE="pod-identity-webhook"
export BIN_DIR=${DIR}/bin
export WEBHOOK_DIR=$HOME_DIR/amazon-eks-pod-identity-webhook
export ASSETS_DIR=${DIR}/runtime-assets
export AWS_REGION=us-east-2
export HOSTNAME=s3.$AWS_REGION.amazonaws.com
export BUCKET_POLICY_NAME=${S3_BUCKET_NAME}-policy
export BUCKET_ROLE_NAME=${S3_BUCKET_NAME}-role

aws s3api create-bucket --bucket $OIDC_S3_BUCKET_NAME --create-bucket-configuration "LocationConstraint=${AWS_REGION}"

aws s3api create-bucket --bucket $S3_BUCKET_NAME --create-bucket-configuration "LocationConstraint=${AWS_REGION}"

mkdir -p ${ASSETS_DIR}

oc get -n openshift-kube-apiserver cm -o json bound-sa-token-signing-certs | jq -r '.data["service-account-001.pub"]' > "${ASSETS_DIR}/${PKCS_KEY}"

cat <<EOF > ${ASSETS_DIR}/discovery.json
{
    "issuer": "https://$HOSTNAME/$OIDC_S3_BUCKET_NAME/",
    "jwks_uri": "https://$HOSTNAME/$OIDC_S3_BUCKET_NAME/keys.json",
    "authorization_endpoint": "urn:kubernetes:programmatic_authorization",
    "response_types_supported": [
        "id_token"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "claims_supported": [
        "sub",
        "iss"
    ]
}
EOF


"${BIN_DIR}/self-hosted-linux" -key "${ASSETS_DIR}/${PKCS_KEY}"  | jq '.keys += [.keys[0]] | .keys[1].kid = ""' > "${ASSETS_DIR}/keys.json"

aws s3 cp --acl public-read "${ASSETS_DIR}/discovery.json" s3://$OIDC_S3_BUCKET_NAME/.well-known/openid-configuration

aws s3 cp --acl public-read "${ASSETS_DIR}/keys.json" s3://$OIDC_S3_BUCKET_NAME/keys.json


export FINGERPRINT=`echo | openssl s_client -servername ${HOSTNAME} -showcerts -connect ${HOSTNAME}:443 2>/dev/null | openssl x509 -fingerprint -noout | sed s/://g | sed 's/.*=//'`


cat <<EOF > ${ASSETS_DIR}/create-open-id-connect-provider.json
{
    "Url": "https://$HOSTNAME/$OIDC_S3_BUCKET_NAME",
    "ClientIDList": [
        "sts.amazonaws.com"
    ],
    "ThumbprintList": [
        "$FINGERPRINT"
    ]
}
EOF

##########
##########
# In case open-id-connect-providers need to be delete
export OIDC_IDENTITY_PROVIDER_ARN=$(aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[?ends_with(Arn, '/${OIDC_S3_BUCKET_NAME}')]".Arn --out text)
aws iam delete-open-id-connect-provider --open-id-connect-provider-arn=${OIDC_IDENTITY_PROVIDER_ARN}
##########
##########

export OIDC_IDENTITY_PROVIDER_ARN=$(aws iam create-open-id-connect-provider --cli-input-json file://${ASSETS_DIR}/create-open-id-connect-provider.json)

cat <<EOF > ${ASSETS_DIR}/trust-policy.json
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Principal": {
    "Federated": "$OIDC_IDENTITY_PROVIDER_ARN"
   },
   "Action": "sts:AssumeRoleWithWebIdentity"
  }
 ]
}
EOF


cat <<EOF > ${ASSETS_DIR}/bucket-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::${S3_BUCKET_NAME}"]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": ["arn:aws:s3:::${S3_BUCKET_NAME}/*"]
    }
  ]
}
EOF


export policy_arn=$(aws iam list-policies --query "Policies[?PolicyName=='${BUCKET_POLICY_NAME}'].{ARN:Arn}" --output text)

if [ "${policy_arn}" != "" ]; then
   # Check to see how many policies we have
  policy_versions=$(aws iam list-policy-versions --policy-arn=${policy_arn} --query "Versions[] | length(@)")

  if [ $policy_versions -gt 1 ]; then
    oldest_policy_version=$(aws iam list-policy-versions --policy-arn=${policy_arn} --query "Versions[-1].VersionId")

    echo "Deleting Oldest Policy Version: ${oldest_policy_version}"
    aws iam delete-policy-version --policy-arn=${policy_arn} --version-id=${oldest_policy_version}
  fi

  echo "Creating new Policy Version"
  aws iam create-policy-version --policy-arn ${policy_arn} --policy-document file://${ASSETS_DIR}/bucket-policy.json --set-as-default > /dev/null

else
  echo "Creating new IAM Policy: '${BUCKET_POLICY_NAME}"
  policy_arn=$(aws iam create-policy --policy-name ${BUCKET_POLICY_NAME} --policy-document file://${ASSETS_DIR}/bucket-policy.json --query Policy.Arn --output text)
fi

export role_arn=$(aws iam list-roles --query "Roles[?RoleName=='${BUCKET_ROLE_NAME}'].{ARN:Arn}" --out text)

if [ "${role_arn}" == "" ]; then
  echo "Creating Assume Role Policy"
  role_arn=$(aws iam create-role --role-name ${BUCKET_ROLE_NAME} --assume-role-policy-document file://${ASSETS_DIR}/trust-policy.json --query Role.Arn --output text)
else
  echo "Updating Assime Role Policy"
  aws iam update-assume-role-policy --role-name ${BUCKET_ROLE_NAME} --policy-document file://${ASSETS_DIR}/trust-policy.json > /dev/null
fi


aws iam attach-role-policy --role-name ${BUCKET_ROLE_NAME} --policy-arn ${policy_arn}

until oc apply -f "${DIR}/manifests/pod-identity-webhook" 2>/dev/null; do sleep 2; done

oc rollout status deploy/pod-identity-webhook -n $POD_IDENTITY_WEBHOOK_NAMESPACE

echo "Waiting for CSR's to be Created"
until [ "$(oc get csr -o jsonpath="{ .items[?(@.spec.username==\"system:serviceaccount:$POD_IDENTITY_WEBHOOK_NAMESPACE:pod-identity-webhook\")].metadata.name}")" != "" ]; do sleep 2; done


echo "Approving CSR's"
for csr in `oc get csr -n ${POD_IDENTITY_WEBHOOK_NAMESPACE} -o name`; do
  oc adm certificate approve $csr
done


echo "Patching OpenShift Cluster Authentication"
oc patch authentication.config.openshift.io cluster --type "json" -p="[{\"op\": \"replace\", \"path\": \"/spec/serviceAccountIssuer\", \"value\":\"https://$HOSTNAME/$OIDC_S3_BUCKET_NAME\"}]"


echo "Creating Mutating Webhook"
export CA_BUNDLE=$(oc get configmap -n kube-system extension-apiserver-authentication -o=jsonpath='{.data.client-ca-file}' | base64 | tr -d '\n')


(
cat <<EOF
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: pod-identity-webhook
  namespace: pod-identity-webhook
webhooks:
- name: pod-identity-webhook.amazonaws.com
  failurePolicy: Ignore
  clientConfig:
    service:
      name: pod-identity-webhook
      namespace: pod-identity-webhook
      path: "/mutate"
    caBundle: ${CA_BUNDLE}
  rules:
  - operations: [ "CREATE" ]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
EOF
 ) | oc apply -f-


echo "Rolling Webhook pods"
oc delete pods -n ${POD_IDENTITY_WEBHOOK_NAMESPACE} -l=app.kubernetes.io/component=webhook
sleep 15


echo "Creating Sample Application Resources"
oc apply -f "${DIR}/manifests/sample-app/namespace.yaml"


(
cat <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    sts.amazonaws.com/role-arn: "${role_arn}"
  name: s3-manager
  namespace: sample-iam-webhook-app
EOF
 ) | oc apply -f-


oc apply -f "${DIR}/manifests/sample-app/deployment.yaml"

echo "Setup Completed Successfully!"


---
