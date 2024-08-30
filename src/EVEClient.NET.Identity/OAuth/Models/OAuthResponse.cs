using System.Text.Json;

namespace EVEClient.NET.Identity.OAuth
{
    public class OAuthResponse : IDisposable
    {
        /// <summary>
        /// Indicates whether the response is successful.
        /// </summary>
        public virtual bool IsSuccessed => Error == null && ErrorDescription == null && HttpResponse.IsSuccessStatusCode;

        /// <summary>
        /// Gets or sets error message from response body.
        /// </summary>
        public string? Error { get; protected set; }

        /// <summary>
        /// Gets or sets error description from response body.
        /// </summary>
        public string? ErrorDescription { get; protected set; }

        /// <summary>
        /// Gets the <see cref="HttpResponseMessage"/>.
        /// </summary>
        internal HttpResponseMessage HttpResponse { get; }

        /// <summary>
        /// Gets the Json representation of the body response.
        /// </summary>
        internal JsonDocument JsonResponse { get; }

        public OAuthResponse(HttpResponseMessage httpResponseMessage, string bodyResponse)
        {
            HttpResponse = httpResponseMessage;
            JsonResponse = JsonDocument.Parse(bodyResponse);

            if (!httpResponseMessage.IsSuccessStatusCode)
            {
                PrepareStandardError(JsonResponse);
            }
        }

        public void Dispose()
        {
            JsonResponse.Dispose();
        }

        protected virtual void PrepareStandardError(JsonDocument response)
        {
            var root = response.RootElement;

            if (root.TryGetProperty("error", out var error))
            {
                Error = error.ToString();
            }

            if (root.TryGetProperty("error_description", out var errorDescription))
            {
                ErrorDescription = errorDescription.ToString();
            }
        }
    }
}
