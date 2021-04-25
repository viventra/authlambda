using Amazon.CDK;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Authlambda
{
    sealed class Program
    {
        public static void Main(string[] args)
        {
            var app = new App();

            var theEnvironment = new Amazon.CDK.Environment() {
                Region = "ap-south-1"
            };

            var theFunctionsStack = new AuthlambdaFunctionsStack(app, "AuthlambdaFunctionsStack", new StackProps(){
                Env = theEnvironment
            });

            new AuthlambdaStack(app, "AuthlambdaStack", new AuthlambdaStackProps() {
                functionsStack = theFunctionsStack,
                Env = theEnvironment
            });

            app.Synth();
        }
    }
}
