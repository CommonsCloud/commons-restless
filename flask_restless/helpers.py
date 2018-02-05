"""
    flask.ext.restless.helpers
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Helper functions for Flask-Restless.

    :copyright: 2012 Jeffrey Finkelstein <jeffrey.finkelstein@gmail.com>
    :license: GNU AGPLv3+ or BSD

"""
import copy
import datetime
import inspect
import uuid
import json

from dateutil.parser import parse as parse_datetime
from sqlalchemy import Date
from sqlalchemy import DateTime
from sqlalchemy import Interval
from sqlalchemy import or_
from sqlalchemy.exc import NoInspectionAvailable
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.associationproxy import AssociationProxy
from sqlalchemy.ext import hybrid
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import ColumnProperty
from sqlalchemy.orm import RelationshipProperty as RelProperty
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.orm.attributes import QueryableAttribute
from sqlalchemy.orm.query import Query
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import _BinaryExpression
from sqlalchemy.sql.expression import ColumnElement
from sqlalchemy.inspection import inspect as sqlalchemy_inspect

from sqlalchemy import and_ as AND
from sqlalchemy import or_ as OR

from geoalchemy2.elements import WKBElement
import geoalchemy2.functions as geofunc

#: Names of attributes which should definitely not be considered relations when
#: dynamically computing a list of relations of a SQLAlchemy model.
RELATION_BLACKLIST = ('query', 'query_class', '_sa_class_manager',
                      '_decl_class_registry')


#: Names of columns which should definitely not be considered user columns to
#: be included in a dictionary representation of a model.
COLUMN_BLACKLIST = ('_sa_polymorphic_on', )

#: Types which should be considered columns of a model when iterating over all
#: attributes of a model class.
COLUMN_TYPES = (InstrumentedAttribute, hybrid_property)

#: Strings which, when received by the server as the value of a date or time
#: field, indicate that the server should use the current time when setting the
#: value of the field.
CURRENT_TIME_MARKERS = ('CURRENT_TIMESTAMP', 'CURRENT_DATE', 'LOCALTIMESTAMP')


def partition(l, condition):
    """Returns a pair of lists, the left one containing all elements of `l` for
    which `condition` is ``True`` and the right one containing all elements of
    `l` for which `condition` is ``False``.

    `condition` is a function that takes a single argument (each individual
    element of the list `l`) and returns either ``True`` or ``False``.

    """
    return [x for x in l if condition(x)], [x for x in l if not condition(x)]


def session_query(session, model):
    """Returns a SQLAlchemy query object for the specified `model`.

    If `model` has a ``query`` attribute already, ``model.query`` will be
    returned. If the ``query`` attribute is callable ``model.query()`` will be
    returned instead.

    If `model` has no such attribute, a query based on `session` will be
    created and returned.

    """
    if hasattr(model, 'query'):
        if callable(model.query):
            query = model.query()
        else:
            query = model.query
        if hasattr(query, 'filter'):
            return query
    return session.query(model)


def upper_keys(d):
    """Returns a new dictionary with the keys of `d` converted to upper case
    and the values left unchanged.

    """
    return dict(zip((k.upper() for k in d.keys()), d.values()))


def get_columns(model):
    """Returns a dictionary-like object containing all the columns of the
    specified `model` class.

    This includes `hybrid attributes`_.

    .. _hybrid attributes: http://docs.sqlalchemy.org/en/latest/orm/extensions/hybrid.html

    """
    columns = {}
    for superclass in model.__mro__:
        for name, column in superclass.__dict__.items():
            if isinstance(column, COLUMN_TYPES):
                columns[name] = column
    return columns


def get_relations(model):
    """Returns a list of relation names of `model` (as a list of strings)."""
    return [k for k in dir(model)
            if not (k.startswith('__') or k in RELATION_BLACKLIST)
            and get_related_model(model, k)]


def get_related_model(model, relationname):
    """Gets the class of the model to which `model` is related by the attribute
    whose name is `relationname`.

    """
    if hasattr(model, relationname):
        attr = getattr(model, relationname)
        if hasattr(attr, 'property') \
                and isinstance(attr.property, RelProperty):
            return attr.property.mapper.class_
        if isinstance(attr, AssociationProxy):
            return get_related_association_proxy_model(attr)
    return None


def get_related_association_proxy_model(attr):
    """Returns the model class specified by the given SQLAlchemy relation
    attribute, or ``None`` if no such class can be inferred.

    `attr` must be a relation attribute corresponding to an association proxy.

    """
    prop = attr.remote_attr.property
    for attribute in ('mapper', 'parent'):
        if hasattr(prop, attribute):
            return getattr(prop, attribute).class_
    return None


def has_field(model, fieldname):
    """Returns ``True`` if the `model` has the specified field
    or if it has a settable hybrid property for this field name.

    """
    descriptors_data = sqlalchemy_inspect(model).all_orm_descriptors._data
    if fieldname in descriptors_data and hasattr(descriptors_data[fieldname], 'fset'):
        return getattr(descriptors_data[fieldname], 'fset') is not None
    return hasattr(model, fieldname)


def get_field_type(model, fieldname):
    """Helper which returns the SQLAlchemy type of the field.
    """
    field = getattr(model, fieldname)
    if isinstance(field, ColumnElement):
        fieldtype = field.type
    else:
        if isinstance(field, AssociationProxy):
            field = field.remote_attr
        if hasattr(field, 'property'):
            prop = field.property
            if isinstance(prop, RelProperty):
                return None
            fieldtype = prop.columns[0].type
        else:
            return None
    return fieldtype


def is_date_field(model, fieldname):
    """Returns ``True`` if and only if the field of `model` with the specified
    name corresponds to either a :class:`datetime.date` object or a
    :class:`datetime.datetime` object.
    """
    fieldtype = get_field_type(model, fieldname)
    return isinstance(fieldtype, Date) or isinstance(fieldtype, DateTime)


def is_interval_field(model, fieldname):
    """Returns ``True`` if and only if the field of `model` with the specified
    name corresponds to a :class:`datetime.timedelta` object.
    """
    fieldtype = get_field_type(model, fieldname)
    return isinstance(fieldtype, Interval)


def assign_attributes(model, **kwargs):
    """Assign all attributes from the supplied `kwargs` dictionary to the
    model. This does the same thing as the default declarative constructor,
    when provided a dictionary of attributes and values.

    """
    cls = type(model)
    for field, value in kwargs.items():
        if not hasattr(cls, field):
            msg = '{0} has no field named "{1!r}"'.format(cls.__name__, field)
            raise TypeError(msg)
        setattr(model, field, value)


def primary_key_names(model):
    """Returns all the primary keys for a model."""
    return [key for key, field in inspect.getmembers(model)
            if isinstance(field, QueryableAttribute)
            and isinstance(field.property, ColumnProperty)
            and field.property.columns[0].primary_key]


def primary_key_name(model_or_instance):
    """Returns the name of the primary key of the specified model or instance
    of a model, as a string.

    If `model_or_instance` specifies multiple primary keys and ``'id'`` is one
    of them, ``'id'`` is returned. If `model_or_instance` specifies multiple
    primary keys and ``'id'`` is not one of them, only the name of the first
    one in the list of primary keys is returned.

    """
    its_a_model = isinstance(model_or_instance, type)
    model = model_or_instance if its_a_model else model_or_instance.__class__
    pk_names = primary_key_names(model)
    return 'id' if 'id' in pk_names else pk_names[0]


def is_like_list(instance, relation):
    """Returns ``True`` if and only if the relation of `instance` whose name is
    `relation` is list-like.

    A relation may be like a list if, for example, it is a non-lazy one-to-many
    relation, or it is a dynamically loaded one-to-many.

    """
    if relation in instance._sa_class_manager:
        return instance._sa_class_manager[relation].property.uselist
    elif hasattr(instance, relation):
        attr = getattr(instance._sa_instance_state.class_, relation)
        if hasattr(attr, 'property'):
            return attr.property.uselist
    related_value = getattr(type(instance), relation, None)
    if isinstance(related_value, AssociationProxy):
        local_prop = related_value.local_attr.prop
        if isinstance(local_prop, RelProperty):
            return local_prop.uselist
    return False


def is_mapped_class(cls):
    try:
        sqlalchemy_inspect(cls)
        return True
    except:
        return False


# This code was adapted from :meth:`elixir.entity.Entity.to_dict` and
# http://stackoverflow.com/q/1958219/108197.
def to_dict(instance, deep=None, exclude=None, include=None,
            exclude_relations=None, include_relations=None,
            include_methods=None, session=None):
    """Returns a dictionary representing the fields of the specified `instance`
    of a SQLAlchemy model.

    The returned dictionary is suitable as an argument to
    :func:`flask.jsonify`; :class:`datetime.date` and :class:`uuid.UUID`
    objects are converted to string representations, so no special JSON encoder
    behavior is required.

    `deep` is a dictionary containing a mapping from a relation name (for a
    relation of `instance`) to either a list or a dictionary. This is a
    recursive structure which represents the `deep` argument when calling
    :func:`!_to_dict` on related instances. When an empty list is encountered,
    :func:`!_to_dict` returns a list of the string representations of the
    related instances.

    If either `include` or `exclude` is not ``None``, exactly one of them must
    be specified. If both are not ``None``, then this function will raise a
    :exc:`ValueError`. `exclude` must be a list of strings specifying the
    columns which will *not* be present in the returned dictionary
    representation of the object (in other words, it is a
    blacklist). Similarly, `include` specifies the only columns which will be
    present in the returned dictionary (in other words, it is a whitelist).

    .. note::

       If `include` is an iterable of length zero (like the empty tuple or the
       empty list), then the returned dictionary will be empty. If `include` is
       ``None``, then the returned dictionary will include all columns not
       excluded by `exclude`.

    `include_relations` is a dictionary mapping strings representing relation
    fields on the specified `instance` to a list of strings representing the
    names of fields on the related model which should be included in the
    returned dictionary; `exclude_relations` is similar.

    `include_methods` is a list mapping strings to method names which will
    be called and their return values added to the returned dictionary.

    """
    if (exclude is not None or exclude_relations is not None) and \
            (include is not None or include_relations is not None):
        raise ValueError('Cannot specify both include and exclude.')
    # create a list of names of columns, including hybrid properties
    instance_type = type(instance)
    columns = []
    try:
        inspected_instance = sqlalchemy_inspect(instance_type)
        column_attrs = inspected_instance.column_attrs.keys()
        descriptors = inspected_instance.all_orm_descriptors.items()
        hybrid_columns = [k for k, d in descriptors
                          if d.extension_type == hybrid.HYBRID_PROPERTY
                          and not (deep and k in deep)]
        columns = column_attrs + hybrid_columns
    except NoInspectionAvailable:
        return instance
    # filter the columns based on exclude and include values
    if exclude is not None:
        columns = (c for c in columns if c not in exclude)
    elif include is not None:
        columns = (c for c in columns if c in include)
    # create a dictionary mapping column name to value
    result = dict((col, getattr(instance, col)) for col in columns
                  if not (col.startswith('__') or col in COLUMN_BLACKLIST))
    # add any included methods
    if include_methods is not None:
        result.update(dict((method, getattr(instance, method)())
                           for method in include_methods
                           if not '.' in method))
    # Check for objects in the dictionary that may not be serializable by
    # default. Convert datetime objects to ISO 8601 format, convert UUID
    # objects to hexadecimal strings, etc.
    for key, value in result.items():
        if "password" == key:
            result[key] = "****************"
        elif isinstance(value, WKBElement):
            # print 'We need to convert to GeoJSON here', session.scalar(geofunc.ST_AsGeoJSON(value)), value
            # print 'wkb.loads(value)', wkb.loads(value)
            result[key] = json.loads(session.scalar(geofunc.ST_AsGeoJSON(value)))
        elif isinstance(value, (datetime.date, datetime.time)):
            result[key] = value.isoformat()
        elif isinstance(value, uuid.UUID):
            result[key] = str(value)
        elif key not in column_attrs and is_mapped_class(type(value)):
            result[key] = to_dict(value)
    # recursively call _to_dict on each of the `deep` relations
    deep = deep or {}
    for relation, rdeep in deep.items():
        # Get the related value so we can see if it is None, a list, a query
        # (as specified by a dynamic relationship loader), or an actual
        # instance of a model.
        relatedvalue = getattr(instance, relation)
        if relatedvalue is None:
            result[relation] = None
            continue
        # Determine the included and excluded fields for the related model.
        newexclude = None
        newinclude = None
        if exclude_relations is not None and relation in exclude_relations:
            newexclude = exclude_relations[relation]
        elif (include_relations is not None and
              relation in include_relations):
            newinclude = include_relations[relation]
        # Determine the included methods for the related model.
        newmethods = None
        if include_methods is not None:
            newmethods = [method.split('.', 1)[1] for method in include_methods
                          if method.split('.', 1)[0] == relation]
        if is_like_list(instance, relation):
            result[relation] = [to_dict(inst, rdeep, exclude=newexclude,
                                        include=newinclude,
                                        include_methods=newmethods,
                                        session=session)
                                for inst in relatedvalue]
            continue
        # If the related value is dynamically loaded, resolve the query to get
        # the single instance.
        if isinstance(relatedvalue, Query):
            relatedvalue = relatedvalue.one()
        result[relation] = to_dict(relatedvalue, rdeep, exclude=newexclude,
                                   include=newinclude,
                                   include_methods=newmethods,
                                   session=session)

    """
    Since we are producing GeoJSON instead of regular JSON we need to add
    a `type` and a `properties` field to the object
    """

    #
    # Must use copy here, otherwise when we delete it, this variable will
    # emptied out as well.
    #
    # @see https://docs.python.org/2/library/copy.html
    #
    if 'geometry' in result:
        geometry = copy.deepcopy(result['geometry'])
        result.pop('geometry', None)
    else:
        geometry = None

    feature = {
        'id': result.get('id'),
        'geometry': geometry,
        'properties': result,
        'type': 'Feature'
    }

    return feature


def evaluate_functions(session, model, functions, search_params):
    """Executes each of the SQLAlchemy functions specified in ``functions``, a
    list of dictionaries of the form described below, on the given model and
    returns a dictionary mapping function name (slightly modified, see below)
    to result of evaluation of that function.

    `session` is the SQLAlchemy session in which all database transactions will
    be performed.

    `model` is the SQLAlchemy model class on which the specified functions will
    be evaluated.

    ``functions`` is a list of dictionaries of the form::

        {'name': 'avg', 'field': 'amount'}

    For example, if you want the sum and the average of the field named
    "amount"::

        >>> # assume instances of Person exist in the database...
        >>> f1 = dict(name='sum', field='amount')
        >>> f2 = dict(name='avg', field='amount')
        >>> evaluate_functions(Person, [f1, f2])
        {'avg__amount': 456, 'sum__amount': 123}

    The return value is a dictionary mapping ``'<funcname>__<fieldname>'`` to
    the result of evaluating that function on that field. If `model` is
    ``None`` or `functions` is empty, this function returns the empty
    dictionary.

    If a field does not exist on a given model, :exc:`AttributeError` is
    raised. If a function does not exist,
    :exc:`sqlalchemy.exc.OperationalError` is raised. The former exception will
    have a ``field`` attribute which is the name of the field which does not
    exist. The latter exception will have a ``function`` attribute which is the
    name of the function with does not exist.

    """
    if not model or not functions:
        return {}
    processed = []
    funcnames = []

    """
    """
    q = {
        'filters': search_params
    }

    if isinstance(q, dict):
        searchparams = SearchParameters.from_dictionary(q)

    filters = QueryBuilder._create_filters(model, searchparams)
    """
    """

    for function in functions:
        funcname, fieldname = function['name'], function['field']
        # We retrieve the function by name from the SQLAlchemy ``func``
        # module and the field by name from the model class.
        #
        # If the specified field doesn't exist, this raises AttributeError.
        funcobj = getattr(func, funcname)
        try:
            field = getattr(model, fieldname)
        except AttributeError as exception:
            exception.field = fieldname
            raise exception
        # Time to store things to be executed. The processed list stores
        # functions that will be executed in the database and funcnames
        # contains names of the entries that will be returned to the
        # caller.
        funcnames.append('{0}__{1}'.format(funcname, fieldname))
        processed.append(funcobj(field))
    # Evaluate all the functions at once and get an iterable of results.
    try:
        evaluateFiltered = session.query(*processed).filter(searchparams.junction(*filters)).one()

        evaluated = session.query(*processed).one()
    except OperationalError as exception:
        # HACK original error message is of the form:
        #
        #    '(OperationalError) no such function: bogusfuncname'
        original_error_msg = exception.args[0]
        bad_function = original_error_msg[37:]
        exception.function = bad_function
        raise exception
    return dict(zip(funcnames, evaluateFiltered))


def query_by_primary_key(session, model, primary_key_value, licensee, primary_key=None):
    """Returns a SQLAlchemy query object containing the result of querying
    `model` for instances whose primary key has the value `primary_key_value`.

    If `primary_key` is specified, the column specified by that string is used
    as the primary key column. Otherwise, the column named ``id`` is used.

    Presumably, the returned query should have at most one element.

    """
    pk_name = primary_key or primary_key_name(model)
    query = session_query(session, model)

    # return query.filter(getattr(model, pk_name) == primary_key_value)

    """

    ***VIABLE INDUSTRIES MODIFICATION***

    Changed to enable us to do Group specific filtering

    """
    if hasattr(model, 'licensee') and licensee:
        try:
            return query.filter(getattr(model, pk_name) == primary_key_value).filter(or_(model.licensee == licensee, model.licensee == None))
        except InvalidRequestError:
            return query.filter(getattr(model, pk_name) == primary_key_value)
        except:
            return query.filter(getattr(model, pk_name) == primary_key_value).filter(or_(model.licensee.any(id=licensee)))
    else:
        return query.filter(getattr(model, pk_name) == primary_key_value)
    """
    / VIABLE INDUSTRIES MODIFICATION
    """

def get_by(session, model, primary_key_value, primary_key=None, licensee=None):
    """Returns the first instance of `model` whose primary key has the value
    `primary_key_value`, or ``None`` if no such instance exists.

    If `primary_key` is specified, the column specified by that string is used
    as the primary key column. Otherwise, the column named ``id`` is used.

    """
    result = query_by_primary_key(session, model, primary_key_value,
                                  licensee, primary_key)
    return result.first()


def get_or_create(session, model, attrs):
    """Returns the single instance of `model` whose primary key has the
    value found in `attrs`, or initializes a new instance if no primary key
    is specified.

    Before returning the new or existing instance, its attributes are
    assigned to the values supplied in the `attrs` dictionary.

    This method does not commit the changes made to the session; the
    calling function has that responsibility.

    """
    # Not a full relation, probably just an association proxy to a scalar
    # attribute on the remote model.
    if not isinstance(attrs, dict):
        return attrs
    # Recurse into nested relationships
    for rel in get_relations(model):
        if rel not in attrs:
            continue
        if isinstance(attrs[rel], list):
            attrs[rel] = [get_or_create(session, get_related_model(model, rel),
                                        r) for r in attrs[rel]]
        else:
            attrs[rel] = get_or_create(session, get_related_model(model, rel),
                                       attrs[rel])
    # Find private key names
    pk_names = primary_key_names(model)
    attrs = strings_to_dates(model, attrs)
    # If all of the primary keys were included in `attrs`, try to update
    # an existing row.
    if all(k in attrs for k in pk_names):
        # Determine the sub-dictionary of `attrs` which contains the mappings
        # for the primary keys.
        pk_values = dict((k, v) for (k, v) in attrs.items()
                         if k in pk_names)
        # query for an existing row which matches all the specified
        # primary key values.
        instance = session_query(session, model).filter_by(**pk_values).first()
        if instance is not None:
            assign_attributes(instance, **attrs)
            return instance
    # If some of the primary keys were missing, or the row wasn't found,
    # create a new row.
    return model(**attrs)


def strings_to_dates(model, dictionary):
    """Returns a new dictionary with all the mappings of `dictionary` but
    with date strings and intervals mapped to :class:`datetime.datetime` or
    :class:`datetime.timedelta` objects.

    The keys of `dictionary` are names of fields in the model specified in the
    constructor of this class. The values are values to set on these fields. If
    a field name corresponds to a field in the model which is a
    :class:`sqlalchemy.types.Date`, :class:`sqlalchemy.types.DateTime`, or
    :class:`sqlalchemy.Interval`, then the returned dictionary will have the
    corresponding :class:`datetime.datetime` or :class:`datetime.timedelta`
    Python object as the value of that mapping in place of the string.

    This function outputs a new dictionary; it does not modify the argument.

    """
    result = {}
    for fieldname, value in dictionary.items():
        if is_date_field(model, fieldname) and value is not None:
            if value.strip() == '':
                result[fieldname] = None
            elif value in CURRENT_TIME_MARKERS:
                result[fieldname] = getattr(func, value.lower())()
            else:
                result[fieldname] = parse_datetime(value)
        elif (is_interval_field(model, fieldname) and value is not None
              and isinstance(value, int)):
            result[fieldname] = datetime.timedelta(seconds=value)
        else:
            result[fieldname] = value
    return result


def count(session, query):
    """Returns the count of the specified `query`.

    This function employs an optimization that bypasses the
    :meth:`sqlalchemy.orm.Query.count` method, which can be very slow for large
    queries.

    """
    counts = query.selectable.with_only_columns([func.count()])
    num_results = session.execute(counts.order_by(None)).scalar()
    if num_results is None or query._limit:
        return query.count()
    return num_results

def _sub_operator(model, argument, fieldname):
    """Recursively calls :func:`QueryBuilder._create_operation` when argument
    is a dictionary of the form specified in :ref:`search`.

    This function is for use with the ``has`` and ``any`` search operations.

    """
    if isinstance(model, InstrumentedAttribute):
        submodel = model.property.mapper.class_
    elif isinstance(model, AssociationProxy):
        submodel = get_related_association_proxy_model(model)
    else:  # TODO what to do here?
        pass
    if isinstance(argument, dict):
        fieldname = argument['name']
        operator = argument['op']
        argument = argument.get('val')
        relation = None
        if '__' in fieldname:
            fieldname, relation = fieldname.split('__')
        return QueryBuilder._create_operation(submodel, fieldname, operator,
                                              argument, relation)
    # Support legacy has/any with implicit eq operator
    return getattr(submodel, fieldname) == argument


#: The mapping from operator name (as accepted by the search method) to a
#: function which returns the SQLAlchemy expression corresponding to that
#: operator.
#:
#: Each of these functions accepts either one, two, or three arguments. The
#: first argument is the field object on which to apply the operator. The
#: second argument, where it exists, is either the second argument to the
#: operator or a dictionary as described below. The third argument, where it
#: exists, is the name of the field.
#:
#: For functions that accept three arguments, the second argument may be a
#: dictionary containing ``'name'``, ``'op'``, and ``'val'`` mappings so that
#: :func:`QueryBuilder._create_operation` may be applied recursively. For more
#: information and examples, see :ref:`search`.
#:
#: Some operations have multiple names. For example, the equality operation can
#: be described by the strings ``'=='``, ``'eq'``, ``'equals'``, etc.
OPERATORS = {
    # Operators which accept a single argument.
    'is_null': lambda f: f == None,
    'is_not_null': lambda f: f != None,
    # TODO what are these?
    'desc': lambda f: f.desc,
    'asc': lambda f: f.asc,
    # Operators which accept two arguments.
    '==': lambda f, a: f == a,
    'eq': lambda f, a: f == a,
    'equals': lambda f, a: f == a,
    'equal_to': lambda f, a: f == a,
    '!=': lambda f, a: f != a,
    'ne': lambda f, a: f != a,
    'neq': lambda f, a: f != a,
    'not_equal_to': lambda f, a: f != a,
    'does_not_equal': lambda f, a: f != a,
    '>': lambda f, a: f > a,
    'gt': lambda f, a: f > a,
    '<': lambda f, a: f < a,
    'lt': lambda f, a: f < a,
    '>=': lambda f, a: f >= a,
    'ge': lambda f, a: f >= a,
    'gte': lambda f, a: f >= a,
    'geq': lambda f, a: f >= a,
    '<=': lambda f, a: f <= a,
    'le': lambda f, a: f <= a,
    'lte': lambda f, a: f <= a,
    'leq': lambda f, a: f <= a,
    'ilike': lambda f, a: f.ilike(a),
    'like': lambda f, a: f.like(a),
    'in': lambda f, a: f.in_(a),
    'not_in': lambda f, a: ~f.in_(a),
    # Operators which accept three arguments.
    'has': lambda f, a, fn: f.has(_sub_operator(f, a, fn)),
    'any': lambda f, a, fn: f.any(_sub_operator(f, a, fn)),
}


class OrderBy(object):
    """Represents an "order by" in a SQL query expression."""

    def __init__(self, field, direction='asc'):
        """Instantiates this object with the specified attributes.

        `field` is the name of the field by which to order the result set.

        `direction` is either ``'asc'`` or ``'desc'``, for "ascending" and
        "descending", respectively.

        """
        self.field = field
        self.direction = direction

    def __repr__(self):
        """Returns a string representation of this object."""
        return '<OrderBy {0}, {1}>'.format(self.field, self.direction)


class Filter(object):
    """Represents a filter to apply to a SQL query.

    A filter can be, for example, a comparison operator applied to a field of a
    model and a value or a comparison applied to two fields of the same
    model. For more information on possible filters, see :ref:`search`.

    """

    def __init__(self, fieldname, operator, argument=None, otherfield=None):
        """Instantiates this object with the specified attributes.

        `fieldname` is the name of the field of a model which will be on the
        left side of the operator.

        `operator` is the string representation of an operator to apply. The
        full list of recognized operators can be found at :ref:`search`.

        If `argument` is specified, it is the value to place on the right side
        of the operator. If `otherfield` is specified, that field on the model
        will be placed on the right side of the operator.

        .. admonition:: About `argument` and `otherfield`

           Some operators don't need either argument and some need exactly one.
           However, this constructor will not raise any errors or otherwise
           inform you of which situation you are in; it is basically just a
           named tuple. Calling code must handle errors caused by missing
           required arguments.

        """
        self.fieldname = fieldname
        self.operator = operator
        self.argument = argument
        self.otherfield = otherfield

    def __repr__(self):
        """Returns a string representation of this object."""
        return '<Filter {0} {1} {2}>'.format(self.fieldname, self.operator,
                                             self.argument or self.otherfield)

    @staticmethod
    def from_dictionary(dictionary):
        """Returns a new :class:`Filter` object with arguments parsed from
        `dictionary`.

        `dictionary` is a dictionary of the form::

            {'name': 'age', 'op': 'lt', 'val': 20}

        or::

            {'name': 'age', 'op': 'lt', 'other': height}

        where ``dictionary['name']`` is the name of the field of the model on
        which to apply the operator, ``dictionary['op']`` is the name of the
        operator to apply, ``dictionary['val']`` is the value on the right to
        which the operator will be applied, and ``dictionary['other']`` is the
        name of the other field of the model to which the operator will be
        applied.

        """
        fieldname = dictionary.get('name')
        operator = dictionary.get('op')
        argument = dictionary.get('val')
        otherfield = dictionary.get('field')
        return Filter(fieldname, operator, argument, otherfield)


class SearchParameters(object):
    """Aggregates the parameters for a search, including filters, search type,
    limit, offset, and order by directives.

    """

    def __init__(self, filters=None, limit=None, offset=None, order_by=None,
                 junction=None):
        """Instantiates this object with the specified attributes.

        `filters` is a list of :class:`Filter` objects, representing filters to
        be applied during the search.

        `limit`, if not ``None``, specifies the maximum number of results to
        return in the search.

        `offset`, if not ``None``, specifies the number of initial results to
        skip in the result set.

        `order_by` is a list of :class:`OrderBy` objects, representing the
        ordering directives to apply to the result set which matches the
        search.

        `junction` is either :func:`sqlalchemy.or_` or :func:`sqlalchemy.and_`
        (if ``None``, this will default to :func:`sqlalchemy.and_`), specifying
        how the filters should be interpreted (that is, as a disjunction or a
        conjunction).

        """
        self.filters = filters or []
        self.limit = limit
        self.offset = offset
        self.order_by = order_by or []
        self.junction = junction or AND

    def __repr__(self):
        """Returns a string representation of the search parameters."""
        template = ('<SearchParameters filters={0}, order_by={1}, limit={2},'
                    ' offset={3}, junction={4}>')
        return template.format(self.filters, self.order_by, self.limit,
                               self.offset, self.junction.__name__)

    @staticmethod
    def from_dictionary(dictionary):
        """Returns a new :class:`SearchParameters` object with arguments parsed
        from `dictionary`.

        `dictionary` is a dictionary of the form::

            {
              'filters': [{'name': 'age', 'op': 'lt', 'val': 20}, ...],
              'order_by': [{'field': 'age', 'direction': 'desc'}, ...]
              'limit': 10,
              'offset': 3,
              'disjunction': True
            }

        where ``dictionary['filters']`` is the list of :class:`Filter` objects
        (in dictionary form), ``dictionary['order_by']`` is the list of
        :class:`OrderBy` objects (in dictionary form), ``dictionary['limit']``
        is the maximum number of matching entries to return,
        ``dictionary['offset']`` is the number of initial entries to skip in
        the matching result set, and ``dictionary['disjunction']`` is whether
        the filters should be joined as a disjunction or conjunction.

        The provided dictionary may have other key/value pairs, but they are
        ignored.

        """
        # for the sake of brevity...
        from_dict = Filter.from_dictionary
        filters = [from_dict(f) for f in dictionary.get('filters', [])]
        order_by_list = dictionary.get('order_by', [])
        order_by = [OrderBy(**o) for o in order_by_list]
        limit = dictionary.get('limit')
        offset = dictionary.get('offset')
        disjunction = dictionary.get('disjunction')
        junction = OR if disjunction else AND
        return SearchParameters(filters=filters, limit=limit, offset=offset,
                                order_by=order_by, junction=junction)


class QueryBuilder(object):
    """Provides a static function for building a SQLAlchemy query object based
    on a :class:`SearchParameters` instance.

    Use the static :meth:`create_query` method to create a SQLAlchemy query on
    a given model.

    """

    @staticmethod
    def _create_operation(model, fieldname, operator, argument, relation=None):
        """Translates an operation described as a string to a valid SQLAlchemy
        query parameter using a field or relation of the specified model.

        More specifically, this translates the string representation of an
        operation, for example ``'gt'``, to an expression corresponding to a
        SQLAlchemy expression, ``field > argument``. The recognized operators
        are given by the keys of :data:`OPERATORS`. For more information on
        recognized search operators, see :ref:`search`.

        If `relation` is not ``None``, the returned search parameter will
        correspond to a search on the field named `fieldname` on the entity
        related to `model` whose name, as a string, is `relation`.

        `model` is an instance of a SQLAlchemy declarative model being
        searched.

        `fieldname` is the name of the field of `model` to which the operation
        will be applied as part of the search. If `relation` is specified, the
        operation will be applied to the field with name `fieldname` on the
        entity related to `model` whose name, as a string, is `relation`.

        `operation` is a string representating the operation which will be
         executed between the field and the argument received. For example,
         ``'gt'``, ``'lt'``, ``'like'``, ``'in'`` etc.

        `argument` is the argument to which to apply the `operator`.

        `relation` is the name of the relationship attribute of `model` to
        which the operation will be applied as part of the search, or ``None``
        if this function should not use a related entity in the search.

        This function raises the following errors:
        * :exc:`KeyError` if the `operator` is unknown (that is, not in
          :data:`OPERATORS`)
        * :exc:`TypeError` if an incorrect number of arguments are provided for
          the operation (for example, if `operation` is `'=='` but no
          `argument` is provided)
        * :exc:`AttributeError` if no column with name `fieldname` or
          `relation` exists on `model`

        """
        # raises KeyError if operator not in OPERATORS
        opfunc = OPERATORS[operator]
        argspec = inspect.getargspec(opfunc)
        # in Python 2.6 or later, this should be `argspec.args`
        numargs = len(argspec[0])
        # raises AttributeError if `fieldname` or `relation` does not exist
        field = getattr(model, relation or fieldname)
        # each of these will raise a TypeError if the wrong number of argments
        # is supplied to `opfunc`.
        if numargs == 1:
            return opfunc(field)
        if argument is None:
            msg = ('To compare a value to NULL, use the is_null/is_not_null '
                   'operators.')
            raise TypeError(msg)
        if numargs == 2:
            return opfunc(field, argument)
        return opfunc(field, argument, fieldname)

    @staticmethod
    def _create_filters(model, search_params):
        """Returns the list of operations on `model` specified in the
        :attr:`filters` attribute on the `search_params` object.

        `search-params` is an instance of the :class:`SearchParameters` class
        whose fields represent the parameters of the search.

        Raises one of :exc:`AttributeError`, :exc:`KeyError`, or
        :exc:`TypeError` if there is a problem creating the query. See the
        documentation for :func:`_create_operation` for more information.

        Pre-condition: the ``search_params.filters`` is a (possibly empty)
        iterable.

        """
        filters = []
        for filt in search_params.filters:
            fname = filt.fieldname
            val = filt.argument
            # get the relationship from the field name, if it exists
            relation = None
            if '__' in fname:
                relation, fname = fname.split('__')
            # get the other field to which to compare, if it exists
            if filt.otherfield:
                val = getattr(model, filt.otherfield)
            # for the sake of brevity...
            create_op = QueryBuilder._create_operation
            param = create_op(model, fname, filt.operator, val, relation)
            filters.append(param)
        return filters

    @staticmethod
    def create_query(session, model, search_params):
        """Builds an SQLAlchemy query instance based on the search parameters
        present in ``search_params``, an instance of :class:`SearchParameters`.

        This method returns a SQLAlchemy query in which all matched instances
        meet the requirements specified in ``search_params``.

        `model` is SQLAlchemy declarative model on which to create a query.

        `search_params` is an instance of :class:`SearchParameters` which
        specify the filters, order, limit, offset, etc. of the query.

        Building the query proceeds in this order:
        1. filtering the query
        2. ordering the query
        3. limiting the query
        4. offsetting the query

        Raises one of :exc:`AttributeError`, :exc:`KeyError`, or
        :exc:`TypeError` if there is a problem creating the query. See the
        documentation for :func:`_create_operation` for more information.

        """
        # Adding field filters
        query = session_query(session, model)
        # may raise exception here
        filters = QueryBuilder._create_filters(model, search_params)
        query = query.filter(search_params.junction(*filters))

        # Order the search. If no order field is specified in the search
        # parameters, order by primary key.
        if search_params.order_by:
            for val in search_params.order_by:
                field = getattr(model, val.field)
                direction = getattr(field, val.direction)
                query = query.order_by(direction())
        else:
            pks = primary_key_names(model)
            pk_order = (getattr(model, field).asc() for field in pks)
            query = query.order_by(*pk_order)

        # Limit it
        if search_params.limit:
            query = query.limit(search_params.limit)
        if search_params.offset:
            query = query.offset(search_params.offset)

        if hasattr(model, 'licensee'):
            licensee = json.loads(request.args.get('licensee', None))

            try:
                return query.filter(or_(model.licensee == licensee, model.licensee == None))
            except:
                return query.filter(or_(model.licensee.any(id=licensee)))
        else:
            return query
