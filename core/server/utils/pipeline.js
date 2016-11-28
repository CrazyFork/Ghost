/**
 * # Pipeline Utility
 *
 * Based on pipeline.js from when.js:
 * https://github.com/cujojs/when/blob/3.7.4/pipeline.js
 */
var Promise = require('bluebird');

/**
 * run functions of promise result in a pipeline
 *  task: Array[List[()=>Promise[any]]]
 *  initial arguments: value | Promise[any]
 */
function pipeline(tasks /*, initial arguments */) {
    var args = Array.prototype.slice.call(arguments, 1),

        runTask = function (task, args) {
            // Self-optimizing function to run first task with multiple
            // args using apply, but subsequent tasks via direct invocation
            runTask = function (task, arg) {
                return task(arg);
            };

            return task.apply(null, args);
        };

    // Resolve any promises for the arguments passed in first
    return Promise.all(args).then(function (args) {
        // Iterate through the tasks passing args from one into the next
        return Promise.reduce(tasks, function (arg, task) {
            return runTask(task, arg);
        }, args);
    });
}

module.exports = pipeline;
