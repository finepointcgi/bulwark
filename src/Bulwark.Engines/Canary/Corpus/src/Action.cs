// Canary: ASP.NET action parameter concatenated into SQL.
class ItemsController : ControllerBase
{
    public IActionResult Get([FromQuery] string id)
    {
        var command = new SqlCommand("SELECT * FROM Items WHERE Id=" + id, connection);
        return Ok();
    }
}
