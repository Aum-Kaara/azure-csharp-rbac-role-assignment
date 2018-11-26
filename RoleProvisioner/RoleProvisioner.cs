using System;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest;
using Microsoft.Rest.Azure.Authentication;
using System.Threading.Tasks;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Threading;
using Microsoft.Azure.Management.Authorization;

namespace RoleProvisioner
{
    internal class CustomLoginCredentials : ServiceClientCredentials
    {
        private string AuthenticationToken { get; set; }

        public CustomLoginCredentials(string token)
        {
            AuthenticationToken = token;
        }

        public override void InitializeServiceClient<T>(ServiceClient<T> client)
        {
        }

        public override async Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            if (AuthenticationToken == null)
            {
                throw new InvalidOperationException("Token Provider Cannot Be Null");
            }
            
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AuthenticationToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //request.Version = new Version(apiVersion);
            await base.ProcessHttpRequestAsync(request, cancellationToken);
        }
    }

    public static class Authorizer
    {
        public static string GetEnvironmentVariable(string name) => Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);

        [FunctionName("RoleProvisioner")]
        public static void Run([TimerTrigger("0 0 0 1 1 *", RunOnStartup = true)]TimerInfo myTimer, TraceWriter log)
        {
            log.Info($"C# Timer trigger function executed at: {DateTime.Now}");

            var tenantId = GetEnvironmentVariable("tenantId");
            var subscriptionId = GetEnvironmentVariable("subscriptionId");
            var resourceGroup = GetEnvironmentVariable("resourceGroupName");
            var storageAccountName = GetEnvironmentVariable("storageAccountName");

            var resourceGroupScope = $"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}";
            var resourceScope = $"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Storage/storageAccounts/{storageAccountName}";
            var ownerRole = $"/subscriptions/'{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
            var assignmentId = Guid.NewGuid().ToString();
            var token = GetAzureAccessTokenFromKeyVault();

            var client = new AuthorizationManagementClient(new CustomLoginCredentials(token));
            client.RoleAssignments.ListForResourceGroup(resourceGroup);
        }

        private static string GetAzureAccessTokenFromKeyVault()
        {
            var clientId = GetEnvironmentVariable("clientId");
            var vaultName = GetEnvironmentVariable("vaultName");
            
            // Use Managed Service Identity
            AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
            var keyVaultClient = new KeyVaultClient(
                new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            
            // List secrets to obtain secret value (assumes single token in vault)
            var vaultUrl = $"https://{vaultName}.vault.azure.net";
            var secrets = keyVaultClient.GetSecretsAsync(vaultUrl)
                .GetAwaiter()
                .GetResult();
            string secretName = null;
            foreach(var secret in secrets)
            {
                secretName = secret.Identifier.Name;
            }
            var vaultSecret = keyVaultClient.GetSecretAsync(vaultUrl, secretName)
                .GetAwaiter()
                .GetResult();

            return vaultSecret.Value; // to be used like $"Bearer {vaultSecret.Value}"
        }
    }
}
