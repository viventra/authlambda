using Amazon.CDK;
using Amazon.CDK.AWS.S3;
using Amazon.CDK.AWS.S3.Deployment;
using Amazon.CDK.AWS.CloudFront;
using Amazon.CDK.AWS.CloudFront.Origins;
using Amazon.CDK.AWS.IAM;

namespace Authlambda
{
    public class AuthlambdaStackProps : StackProps
    {
        public AuthlambdaFunctionsStack functionsStack;
    }

    public class AuthlambdaStack : Stack
    {
        const string cloudfrontOAIName = "E318EOOP7Y2H1E";

        AuthlambdaFunctionsStack functionsStack;
        internal AuthlambdaStack(Construct scope, string id, AuthlambdaStackProps props = null) : base(scope, id, props)
        {
            functionsStack = props.functionsStack;

            Bucket websiteBucket = new Bucket(this, "websiteBucket", new BucketProps() {
                BlockPublicAccess = BlockPublicAccess.BLOCK_ALL,
                PublicReadAccess = false,
                //WebsiteIndexDocument = "index.html",
                RemovalPolicy = RemovalPolicy.DESTROY,
                Cors = new ICorsRule[] {
                    new CorsRule() {
                        AllowedHeaders = new string[] { "Authorization", "Content-Type", "Origin" },
                        AllowedMethods = new HttpMethods[] { HttpMethods.GET, HttpMethods.HEAD },
                        AllowedOrigins = new string[] { "*" }
                    }
                }
            });

            Bucket privateBucket = new Bucket(this, "privateBucket", new BucketProps() {
                BlockPublicAccess = BlockPublicAccess.BLOCK_ALL,
                PublicReadAccess = false,
                RemovalPolicy = RemovalPolicy.DESTROY,
                Cors = new ICorsRule[] {
                    new CorsRule() {
                        AllowedHeaders = new string[] { "Authorization", "Content-Type", "Origin" },
                        AllowedMethods = new HttpMethods[] { HttpMethods.GET, HttpMethods.HEAD },
                        AllowedOrigins = new string[] { "*" }
                    }
                }
            });

            // The S3 bucket deployment for the website
            var websiteDeployment = new BucketDeployment(this, "TestStaticWebsiteDeployment", new BucketDeploymentProps(){
                Sources = new [] {Source.Asset("./src/website")},
                DestinationBucket = websiteBucket,
                RetainOnDelete = false
            });

            var privateDeployment = new BucketDeployment(this, "TestPrivateDeployment", new BucketDeploymentProps(){
                Sources = new [] {Source.Asset("./src/private")},
                DestinationBucket = privateBucket,
                RetainOnDelete = false
            });

            var cloudfrontOAI = OriginAccessIdentity.FromOriginAccessIdentityName(this, "CloudfrontOAIName", cloudfrontOAIName);
            websiteBucket.GrantRead(cloudfrontOAI.GrantPrincipal);
            privateBucket.GrantRead(cloudfrontOAI.GrantPrincipal);

            var cachePolicy = new CachePolicy(this, "TestCachePolicy", new CachePolicyProps() {
                CachePolicyName = "TestCachePolicy",
                Comment = "Cache policy for Testing",
                DefaultTtl = Duration.Seconds(0),
                CookieBehavior = CacheCookieBehavior.All(),
                HeaderBehavior = CacheHeaderBehavior.AllowList(
                    "Authorization",
                    "Content-Type",
                    "Origin"
                ),
                QueryStringBehavior = CacheQueryStringBehavior.All(),
                EnableAcceptEncodingBrotli = false,
                EnableAcceptEncodingGzip = false
            });
            
            var websiteOrigin = new S3Origin(websiteBucket, new S3OriginProps() {
                OriginAccessIdentity = cloudfrontOAI
            });
            var privateOrigin = new S3Origin(privateBucket, new S3OriginProps() {
                OriginAccessIdentity = cloudfrontOAI
            });

            var dummyOrigin = new HttpOrigin("example.com", new HttpOriginProps() {
                ProtocolPolicy = OriginProtocolPolicy.HTTPS_ONLY
            });

            // default behavior is for the privateOrigin
            var defaultPrivateBehavior = new BehaviorOptions {
                AllowedMethods = AllowedMethods.ALLOW_ALL,
                CachePolicy = cachePolicy,
                OriginRequestPolicy = OriginRequestPolicy.CORS_S3_ORIGIN,
                ViewerProtocolPolicy = ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                Origin = privateOrigin,
                EdgeLambdas = new IEdgeLambda[] {
                    new EdgeLambda() {
                        EventType = LambdaEdgeEventType.VIEWER_REQUEST,
                        FunctionVersion = functionsStack.checkAuthHandler.CurrentVersion,
                    },
                    new EdgeLambda() {
                        EventType = LambdaEdgeEventType.ORIGIN_RESPONSE,
                        FunctionVersion = functionsStack.httpHeadersHandler.CurrentVersion
                    }
                }
            };

            // this behavior is for dummy origin
            var parseAuthBehavior = new BehaviorOptions {
                AllowedMethods = AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                CachePolicy = cachePolicy,
                OriginRequestPolicy = OriginRequestPolicy.CORS_S3_ORIGIN,
                ViewerProtocolPolicy = ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                Origin = dummyOrigin,
                EdgeLambdas = new IEdgeLambda[] {
                    new EdgeLambda() {
                        EventType = LambdaEdgeEventType.VIEWER_REQUEST,
                        FunctionVersion = functionsStack.parseAuthHandler.CurrentVersion,
                    }
                }
            };

            var refreshAuthBehavior = new BehaviorOptions {
                AllowedMethods = AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                CachePolicy = cachePolicy,
                OriginRequestPolicy = OriginRequestPolicy.CORS_S3_ORIGIN,
                ViewerProtocolPolicy = ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                Origin = dummyOrigin,
                EdgeLambdas = new IEdgeLambda[] {
                    new EdgeLambda() {
                        EventType = LambdaEdgeEventType.VIEWER_REQUEST,
                        FunctionVersion = functionsStack.refreshAuthHandler.CurrentVersion,
                    }
                }
            };

            var signOutBehavior = new BehaviorOptions {
                AllowedMethods = AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                CachePolicy = cachePolicy,
                OriginRequestPolicy = OriginRequestPolicy.CORS_S3_ORIGIN,
                ViewerProtocolPolicy = ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                Origin = dummyOrigin,
                EdgeLambdas = new IEdgeLambda[] {
                    new EdgeLambda() {
                        EventType = LambdaEdgeEventType.VIEWER_REQUEST,
                        FunctionVersion = functionsStack.signOutHandler.CurrentVersion,
                    }
                }
            };

            Distribution distribution = new Distribution(this, "TestCloudfrontDistribution", new DistributionProps() {
                Comment = "Test Website Distribution",
                DefaultRootObject = "index.html",
                PriceClass = PriceClass.PRICE_CLASS_ALL,
                GeoRestriction = GeoRestriction.Whitelist(new [] {
                    "IN"
                }),
                DefaultBehavior = defaultPrivateBehavior,
            });

            distribution.AddBehavior("/parseauth", dummyOrigin, parseAuthBehavior);
            distribution.AddBehavior("/refreshauth", dummyOrigin, refreshAuthBehavior);
            distribution.AddBehavior("/signout", dummyOrigin, signOutBehavior);

            var domainNameOutput = new CfnOutput(this, "TestWebsiteDistributionDomainName", new CfnOutputProps() {
                Value = distribution.DistributionDomainName
            });
        }

        internal void GrantLambdaRolePermissions() {
             var lambdaRole = new Role(this, "lambdaEdgeRole", new RoleProps() {
                RoleName = "LambdaEdgeRole",
                AssumedBy = new CompositePrincipal(
                    new ServicePrincipal("lambda.amazonaws.com"),
                    new ServicePrincipal("edgelambda.amazonaws.com")
                ),
                ManagedPolicies = new IManagedPolicy[] {
                    ManagedPolicy.FromManagedPolicyArn(this, "AWSLambdaBasicExecutionRoleManagedPolicy", "service-role/AWSLambdaBasicExecutionRole")
                }
            });

            functionsStack.parseAuthHandler.GrantInvoke(lambdaRole);
            functionsStack.checkAuthHandler.GrantInvoke(lambdaRole);
            functionsStack.refreshAuthHandler.GrantInvoke(lambdaRole);
            functionsStack.signOutHandler.GrantInvoke(lambdaRole);
            functionsStack.httpHeadersHandler.GrantInvoke(lambdaRole);
        }

    }
}
