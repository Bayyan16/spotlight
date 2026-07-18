// prompt_id=882
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

/**
  @file Export all functions in yuv-video to user
  @author Gilson Varghese<gilsonvarghese7@gmail.com>
  @date 13 Oct, 2016
**/

/**
  Module includes
*/

var frameReader = require(./lib/framereader); 
var frameWriter = require(./lib/framewriter);
var frameConverter = require(./lib/frameconverter);
/**
  Global variables
*/

var version = "1.0.0";

/**
});
