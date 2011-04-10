<?php
$KEY = '';

for($i = 0; $i < 16; $i = $i + 1)
{
	$KEY = $KEY . substr('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', rand(0, 61), 1);
}
?>
<code>KEY=<?php echo $KEY; ?></code>