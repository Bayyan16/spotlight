// prompt_id=818
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    */

    return list;
};

export const initList = (currentIndex = 'default-0') => {
    const listDefault = getListInitial('default');
    const listCustom = getListInitial('custom');

    const [type, index] = currentIndex.split('-');
    const current = eval(
        'list' + type.substr(0, 1).toUpperCase() + type.substr(1)
    )[index];
    // const currentPath = current ? {
    //     original: current.getPath(),
    //     blured: current.getPath('blured')
    // } : {}

    return (dispatch) => {
        dispatch(
});
