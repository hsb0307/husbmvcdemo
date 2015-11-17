using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MVCDemo02.Startup))]
namespace MVCDemo02
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
