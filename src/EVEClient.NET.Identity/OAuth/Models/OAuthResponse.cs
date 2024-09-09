using System.Text.Json;

namespace EVEClient.NET.Identity.OAuth
{
    public class OAuthResponse : IDisposable
    {
        private bool _disposedValue;

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
        internal JsonDocument JsonResponse { get; private set; }

        public OAuthResponse(HttpResponseMessage httpResponseMessage, string bodyResponse)
        {
            HttpResponse = httpResponseMessage;

            JsonResponse = string.IsNullOrEmpty(bodyResponse)
                ? JsonDocument.Parse("{}")
                : JsonDocument.Parse(bodyResponse);

            if (!httpResponseMessage.IsSuccessStatusCode)
            {
                PrepareStandardError(JsonResponse);
            }
        }

        public void Dispose()
        {
            Dispose(true);
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

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    JsonResponse.Dispose();
                }

                _disposedValue = true;
            }
        }
    }
}
