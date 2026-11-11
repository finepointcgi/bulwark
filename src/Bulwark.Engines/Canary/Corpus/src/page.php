<?php
// Canary: request data reaches echo and a SQL query.
$id = $_GET['id'];
mysqli_query($connection, "SELECT * FROM items WHERE id=" . $id);
echo $_GET['q'];
