using System.Net.Http.Headers;
using System.Text;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.OAuth
{
    public class OAuthRequest : HttpRequestMessage
    {
        /// <summary>
        /// Getys or sets the http method type.
        /// </summary>
        public HttpMethod HttpMethod { get; set; } = HttpMethod.Post;

        /// <summary>
        /// Gets or sets the client identifier.
        /// </summary>
        public string ClientId { get; set; } = default!;

        /// <summary>
        /// Gets or sets the client secret.
        /// </summary>
        public string ClientSecret { get; set; } = default!;

        /// <summary>
        /// Gets or sets additional parameters.
        /// </summary>
        public Parameters Parameters { get; } = new();

        public OAuthRequest()
        {
            Headers.Accept.Clear();
            Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public void Prepare()
        {
            Validate();

            SetupAuthenticationHeaderValue();

            Method = HttpMethod;

            if (Parameters.IsPresent())
            {
                Content = new FormUrlEncodedContent(Parameters);
            }
        }

        protected virtual void SetupAuthenticationHeaderValue()
        {
            var byteArray = Encoding.ASCII.GetBytes(ClientId + ":" + ClientSecret);

            Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
        }

        protected virtual void Validate()
        {
            if (ClientId.IsMissing())
                throw new ArgumentNullException(nameof(ClientId));

            if (ClientSecret.IsMissing())
                throw new ArgumentNullException(nameof(ClientSecret));
        }
    }
}
