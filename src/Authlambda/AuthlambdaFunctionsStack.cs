using Amazon.CDK;
using Amazon.CDK.AWS.Lambda;
using Amazon.CDK.AWS.IAM;
using Amazon.CDK.AWS.CloudFront.Experimental;


namespace Authlambda
{
    public class AuthlambdaFunctionsStack : Stack
    {
        public EdgeFunction parseAuthHandler;
        public EdgeFunction checkAuthHandler;
        public EdgeFunction httpHeadersHandler;
        public EdgeFunction refreshAuthHandler;
        public EdgeFunction signOutHandler;

        internal AuthlambdaFunctionsStack(Construct scope, string id, IStackProps props = null) : base(scope, id, props)
        {
            /*
            loginHandler = new EdgeFunction(this, "loginHandler", new EdgeFunctionProps() {
                Code = Code.FromAsset("src/lambdaEdge"),
                Handler = "login.handler",
                Runtime = Runtime.NODEJS_12_X,
                Description = "Login handler Lambda@Edge"
            });
            
            checkAuthHandler = new EdgeFunction(this, "checkAuthHandler", new EdgeFunctionProps() {
                Code = Code.FromAsset("src/lambdaEdge"),
                Handler = "checkAuth.handler",
                Runtime = Runtime.NODEJS_12_X,
                Description = "Login handler Lambda@Edge"
            });
            */

            parseAuthHandler = new EdgeFunction(this, "parseAuthHandler", new EdgeFunctionProps() {
                Code = Code.FromAsset("src/lambda-edge/parse-auth/dist"),
                Handler = "bundle.handler",
                Runtime = Runtime.NODEJS_12_X,
                Description = "parseAuthHandler Lambda@Edge",
            });

            checkAuthHandler = new EdgeFunction(this, "checkAuthHandler", new EdgeFunctionProps() {
                Code = Code.FromAsset("src/lambda-edge/check-auth/dist"),
                Handler = "bundle.handler",
                Runtime = Runtime.NODEJS_12_X,
                Description = "checkAuthHandler Lambda@Edge",
            });

            httpHeadersHandler = new EdgeFunction(this, "httpHeadersHandler", new EdgeFunctionProps() {
                Code = Code.FromAsset("src/lambda-edge/http-headers/dist"),
                Handler = "bundle.handler",
                Runtime = Runtime.NODEJS_12_X,
                Description = "httpHeadersHandler Lambda@Edge",
            });

            refreshAuthHandler = new EdgeFunction(this, "refreshAuthHandler", new EdgeFunctionProps() {
                Code = Code.FromAsset("src/lambda-edge/refresh-auth/dist"),
                Handler = "bundle.handler",
                Runtime = Runtime.NODEJS_12_X,
                Description = "refreshAuthHandler Lambda@Edge",
            });

            signOutHandler = new EdgeFunction(this, "signOutHandler", new EdgeFunctionProps() {
                Code = Code.FromAsset("src/lambda-edge/sign-out/dist"),
                Handler = "bundle.handler",
                Runtime = Runtime.NODEJS_12_X,
                Description = "signOutHandler Lambda@Edge",
            });
        }


    }
}