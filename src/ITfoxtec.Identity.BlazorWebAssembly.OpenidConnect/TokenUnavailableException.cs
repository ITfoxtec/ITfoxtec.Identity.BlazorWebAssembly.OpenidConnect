using System;
using System.Runtime.Serialization;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    [Serializable]
    public class TokenUnavailableException : Exception
    {
        public TokenUnavailableException() { }
        public TokenUnavailableException(string message) : base(message) { }
        public TokenUnavailableException(string message, Exception inner) : base(message, inner) { }
        protected TokenUnavailableException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
