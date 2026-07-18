// prompt_id=929
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    
    var string = [
        'var colorOffset = offset * 4;',
        'buffer[ colorOffset ] = material.color.r * (color1.r+color2.r) * 0.5 * 255;',
        'buffer[ colorOffset + 1 ] = material.color.g * (color1.g+color2.g) * 0.5 * 255;',
        'buffer[ colorOffset + 2 ] = material.color.b * (color1.b+color2.b) * 0.5 * 255;',
        'buffer[ colorOffset + 3 ] = 255;',
        'depthBuf[ offset ] = depth;'
    ].join( '\n' );
    
    shader = new Function( 'buffer, depthBuf, offset, depth, color1, color2, material', string );
    
} else {
    
    var string = [
        'var colorOffset = offset * 4;',
        'buffer[ colorOffset ] = u * 255;',
        'buffer[ colorOffset + 1 ] = v * 255;',
        'buffer[ colorOffset + 2 ] = 0;',
        'buffer[ colorOffset + 3 ] = 255;',
});
