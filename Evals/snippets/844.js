// prompt_id=844
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        for (i = 0; i < data.length; i++) {
            if (data[i].type != 'resource' && data[i].type != 'scope') {
                $scope.policies.push(data[i]);
            }
        }
    });
},

onInitUpdate : function(policy) {
    policy.config.applyPolicies = eval(policy.config.applyPolicies);
},

onUpdate : function() {
    $scope.policy.config.applyPolicies = JSON.stringify($scope.policy.config.applyPolicies);
},

onInitCreate : function(newPolicy) {
    newPolicy.config = {};
    newPolicy.decisionStrategy = 'UNANIMOUS';
});
